import json
from urllib.parse import urlencode, urljoin
import aiohttp
import logging
import asyncio
import os
from datetime import datetime, timedelta
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
    get_context,
    try_str_to_datetime,
)
import time


# def set_date_on_entity(context, lte_datetime, entity_value):
#     datetimeEntityId = df.EntityId("SoarDatetimeEntity", "latestDatetime")
#     context.signal_entity(
#         datetimeEntityId, "set", {"type": entity_value, "date": lte_datetime}
#     )


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
    ctx: Context, interval: OptionalEndTimeRange
) -> List[str]:
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
    ctx: Context, interval: OptionalEndTimeRange
) -> List[str]:
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
    ctx: Context, threat_id: str
) -> List[Dict[str, str]]:
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
            and remediation_time <= ctx.CLIENT_FILTER_TIME_RANGE.end
        ):
            filtered_messages.append(json.dumps(message, sort_keys=True))
            logging.debug(f"Successfully processed threat message: {message_id}")
        else:
            logging.debug(f"Skipped processing threat message: {message_id}")

    return filtered_messages


async def call_single_case_endpoint(ctx: Context, case_id: str) -> List[Dict[str, str]]:
    endpoint = compute_url(ctx.BASE_URL, f"/cases/{case_id}", params={})
    headers = get_headers(ctx)

    response = await fetch_with_retries(url=endpoint, headers=headers)

    return json.dumps(response, sort_keys=True)


async def get_threats(ctx: Context, output_queue: asyncio.Queue) -> asyncio.Queue:
    intervals = compute_intervals(ctx)
    logging.info("Computed threats intervals\n" + '\n'.join(map(lambda x: f"{str(x.start)} : {str(x.end)}", intervals)))

    assert len(intervals) <= 5, "Intervals more than 5"

    campaign_result = await asyncio.gather(
        *[
            call_threat_campaigns_endpoint(ctx=ctx, interval=interval)
            for interval in intervals
        ]
    )
    threat_ids = list(set(list(itertools.chain(*campaign_result))))

    single_result = await asyncio.gather(
        *[
            call_single_threat_endpoint(ctx=ctx, threat_id=threat_id)
            for threat_id in threat_ids
        ]
    )
    messages = list(set(list(itertools.chain(*single_result))))

    for message in messages:
        record = (MAP_RESOURCE_TO_LOGTYPE[Resource.threats], json.loads(message))
        logging.debug(f"Inserting threat message record {record}")
        await output_queue.put(record)

    return


async def get_cases(ctx: Context, output_queue: asyncio.Queue) -> asyncio.Queue:
    intervals = compute_intervals(ctx)
    logging.info("Computed cases intervals\n" + '\n'.join(map(lambda x: f"{str(x.start)} : {str(x.end)}", intervals)))

    assert len(intervals) <= 5, "Intervals more than 5"

    result = await asyncio.gather(
        *[call_cases_endpoint(ctx=ctx, interval=interval) for interval in intervals]
    )
    case_ids = list(set(list(itertools.chain(*result))))

    cases = await asyncio.gather(
        *[call_single_case_endpoint(ctx=ctx, case_id=case_id) for case_id in case_ids]
    )

    for case in cases:
        record = (MAP_RESOURCE_TO_LOGTYPE[Resource.cases], json.loads(case))
        logging.debug(f"Inserting case record {record}")
        await output_queue.put(record)

    return


#########################

def find_duplicates(arr):
    from collections import Counter
    counts = Counter(arr)
    return [item for item, count in counts.items() if count > 1]

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.INFO)
    os.environ["ABNORMAL_SECURITY_REST_API_TOKEN"] = "121"
    os.environ["API_HOST"] = "http://localhost:3000"
    os.environ["ABNORMAL_LAG_ON_BACKEND_SEC"] = "10"
    os.environ["ABNORMAL_FREQUENCY_MIN"] = "1"
    os.environ["ABNORMAL_LIMIT_MIN"] = "2"
    
    stored_time = datetime.now() - timedelta(minutes=3)
    output_queue = asyncio.Queue()
    try:
        while True:
            ctx = get_context(stored_date_time=stored_time.strftime(TIME_FORMAT))
            asyncio.run(get_threats(ctx=ctx, output_queue=output_queue))

            stored_time = ctx.CURRENT_TIME
            logging.info(f"Sleeping for {ctx.FREQUENCY.total_seconds()} seconds")
            time.sleep(ctx.FREQUENCY.total_seconds())

    except KeyboardInterrupt:
        pass

    idlist = []
    while not output_queue.empty():
        current = output_queue.get_nowait()
        print(current)
        idlist.append(current[1]['abxMessageId'])


    idset = set(idlist)
    maxid = max(idlist)
    duplicates = find_duplicates(idlist)
    missedids = list(filter(lambda x: x not in idset,list(range(1, maxid + 1))))


    print("\n\n\nSummary of the operation")

    print("Ingested values", idlist)
    print(f"Max ID: {maxid}")
    print(f"Duplicates: {duplicates}")
    print(f"Missed IDs: {missedids}" )

    assert len(idset) == len(idlist), "Duplicates exist"
    assert len(duplicates) == 0, "There are duplicates"    
    assert len(missedids) == 0, "There are missed IDs"    
