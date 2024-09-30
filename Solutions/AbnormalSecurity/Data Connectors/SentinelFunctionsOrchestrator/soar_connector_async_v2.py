import json
from urllib.parse import urlencode, urljoin
import aiohttp
import logging
import asyncio
import itertools
from typing import Dict, List
from utils import (
    OptionalEndTimeRange,
    FilterParam,
    MAP_RESOURCE_TO_LOGTYPE,
    Resource,
    TIME_FORMAT,
    compute_intervals,
    Context,
    try_str_to_datetime,
)


def get_query_params(
    filter_param: FilterParam, interval: OptionalEndTimeRange
) -> Dict[str, str]:
    filter = filter_param.name
    filter += f" gte {interval.start.strftime(TIME_FORMAT)}"
    if interval.end is not None:
        filter += f" lte {interval.end.strftime(TIME_FORMAT)}"

    return {"filter": filter}


def get_headers(ctx: Context) -> Dict[str, str]:
    return {
        "X-Abnormal-Trace-Id": str(ctx.TRACE_ID),
        "Authorization": f"Bearer {ctx.API_TOKEN}",
        "Soar-Integration-Origin": "AZURE SENTINEL",
        "Azure-Sentinel-Version": "2024-09-15",
    }


def compute_url(base_url: str, pathname: str, params: Dict[str, str]) -> str:
    endpoint = urljoin(base_url, pathname)

    params_str = urlencode(params)
    if params_str:
        endpoint += f"?{params_str}"

    return endpoint


async def fetch_with_retries(url, retries=3, backoff=1, timeout=10, headers=None):
    async def fetch(session, url):
        async with session.get(url, headers=headers, timeout=timeout) as response:
            if 500 <= response.status < 600:
                raise aiohttp.ClientResponseError(
                    request_info=response.request_info,
                    history=response.history,
                    code=response.status,
                    message=response.reason,
                    headers=response.headers,
                )
            # response.raise_for_status()
            return json.loads(await response.text())

    async with aiohttp.ClientSession() as session:
        for attempt in range(1, retries + 1):
            try:
                response = await fetch(session, url)
                return response
            except aiohttp.ClientResponseError as e:
                if 500 <= e.status < 600:
                    print(f"Attempt {attempt} failed with error: {e}")
                    if attempt == retries:
                        raise
                    else:
                        await asyncio.sleep(backoff**attempt)
                else:
                    raise
            except aiohttp.ClientError as e:
                print(f"Request failed with non-retryable error: {e}")
                raise


async def call_threat_campaigns_endpoint(
    ctx: Context, interval: OptionalEndTimeRange, semaphore: asyncio.Semaphore
) -> List[str]:
    async with semaphore:
        params = get_query_params(
            filter_param=FilterParam.latestTimeRemediated, interval=interval
        )

        threat_campaigns = set()

        nextPageNumber = 1
        while nextPageNumber:
            params["pageNumber"] = nextPageNumber
            endpoint = compute_url(ctx.BASE_URL, "/threats", params)
            headers = get_headers(ctx)

            response = await fetch_with_retries(url=endpoint, headers=headers)
            total = response["total"]
            assert total >= 0

            threat_campaigns.update(
                [threat["threatId"] for threat in response.get("threats", [])]
            )

            nextPageNumber = response.get("nextPageNumber")
            assert nextPageNumber is None or nextPageNumber > 0

            if nextPageNumber is None or nextPageNumber > ctx.MAX_PAGE_NUMBER:
                break

        return list(threat_campaigns)


async def call_cases_endpoint(
    ctx: Context, interval: OptionalEndTimeRange, semaphore: asyncio.Semaphore
) -> List[str]:
    async with semaphore:
        params = get_query_params(
            filter_param=FilterParam.customerVisibleTime, interval=interval
        )

        case_ids = set()

        nextPageNumber = 1
        while nextPageNumber:
            params["pageNumber"] = nextPageNumber
            endpoint = compute_url(ctx.BASE_URL, "/cases", params)
            headers = get_headers(ctx)

            response = await fetch_with_retries(url=endpoint, headers=headers)
            total = response["total"]
            assert total >= 0

            case_ids.update([case["caseId"] for case in response.get("cases", [])])

            nextPageNumber = response.get("nextPageNumber")
            assert nextPageNumber is None or nextPageNumber > 0

            if nextPageNumber is None or nextPageNumber > ctx.MAX_PAGE_NUMBER:
                break

        return list(case_ids)


async def call_single_threat_endpoint(
    ctx: Context, threat_id: str, semaphore: asyncio.Semaphore
) -> List[str]:
    async with semaphore:
        endpoint = compute_url(ctx.BASE_URL, f"/threats/{threat_id}", params={})
        headers = get_headers(ctx)

        response = await fetch_with_retries(url=endpoint, headers=headers)

        filtered_messages = []
        for message in response["messages"]:
            message_id = message["abxMessageId"]
            remediation_time_str = message["remediationTimestamp"]

            remediation_time = try_str_to_datetime(remediation_time_str)
            if (
                remediation_time >= ctx.CLIENT_FILTER_TIME_RANGE.start
                and remediation_time < ctx.CLIENT_FILTER_TIME_RANGE.end
            ):
                filtered_messages.append(json.dumps(message, sort_keys=True))
                logging.debug(f"Successfully processed threat message: {message_id}")
            else:
                logging.debug(f"Skipped processing threat message: {message_id}")

        return filtered_messages


async def call_single_case_endpoint(
    ctx: Context, case_id: str, semaphore: asyncio.Semaphore
) -> str:
    async with semaphore:
        endpoint = compute_url(ctx.BASE_URL, f"/cases/{case_id}", params={})
        headers = get_headers(ctx)

        response = await fetch_with_retries(url=endpoint, headers=headers)

        return json.dumps(response, sort_keys=True)


async def get_threats(ctx: Context, output_queue: asyncio.Queue) -> asyncio.Queue:
    intervals = compute_intervals(ctx)
    logging.info(
        "Computed threats intervals\n"
        + "\n".join(map(lambda x: f"{str(x.start)} : {str(x.end)}", intervals))
    )

    assert len(intervals) <= 5, "Intervals more than 5"
    semaphore = asyncio.Semaphore(ctx.NUM_CONCURRENCY)

    campaign_result = await asyncio.gather(
        *[
            call_threat_campaigns_endpoint(
                ctx=ctx, interval=interval, semaphore=semaphore
            )
            for interval in intervals
        ]
    )
    threat_ids = set(itertools.chain(*campaign_result))

    single_result = await asyncio.gather(
        *[
            call_single_threat_endpoint(
                ctx=ctx, threat_id=threat_id, semaphore=semaphore
            )
            for threat_id in threat_ids
        ]
    )
    messages = set(itertools.chain(*single_result))

    for message in messages:
        record = (MAP_RESOURCE_TO_LOGTYPE[Resource.threats], json.loads(message))
        logging.debug(f"Inserting threat message record {record}")
        await output_queue.put(record)

    return


async def get_cases(ctx: Context, output_queue: asyncio.Queue) -> asyncio.Queue:
    intervals = compute_intervals(ctx)
    logging.info(
        "Computed cases intervals\n"
        + "\n".join(map(lambda x: f"{str(x.start)} : {str(x.end)}", intervals))
    )

    assert len(intervals) <= 5, "Intervals more than 5"
    semaphore = asyncio.Semaphore(ctx.NUM_CONCURRENCY)

    result = await asyncio.gather(
        *[
            call_cases_endpoint(ctx=ctx, interval=interval, semaphore=semaphore)
            for interval in intervals
        ]
    )
    case_ids = set(itertools.chain(*result))

    cases = await asyncio.gather(
        *[
            call_single_case_endpoint(ctx=ctx, case_id=case_id, semaphore=semaphore)
            for case_id in case_ids
        ]
    )

    for case in cases:
        loaded_case = json.loads(case)
        record = (MAP_RESOURCE_TO_LOGTYPE[Resource.cases], loaded_case)
        visible_time = try_str_to_datetime(loaded_case["customerVisibleTime"])
        if visible_time >= ctx.CLIENT_FILTER_TIME_RANGE.start and visible_time < ctx.CLIENT_FILTER_TIME_RANGE.end:
            logging.debug(f"Inserting case record {record}")
            await output_queue.put(record)
        else:
            logging.debug(f"Skipping case record {record}")

    return


