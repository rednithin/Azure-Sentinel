import json
from urllib.parse import urlencode
import aiohttp
import logging
import asyncio
import os
from datetime import datetime, timedelta
from typing import Dict, Any
from asyncio import Queue
from utils import (
    TimeRange,
    FilterTimeRange,
    FilterParam,
    MAP_RESOURCE_TO_LOGTYPE,
    Resource,
    assert_time_range,
    assert_filter_range,
    TIME_FORMAT_WITHMS,
    compute_intervals,
    EnvVariables
)


class AbnromalSoarAPI:
    def __init__(self, api_key: str, env: EnvVariables) -> None:
        self.api_key = api_key
        self.env = env

    def get_header(self):
        """
        returns header for all HTTP requests to Abnormal Security's API
        """
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Soar-Integration-Origin": "AZURE SENTINEL",
            "Azure-Sentinel-Version": "2024-09-15",
        }

    def get_query_params(
        self, filter_param: FilterParam, filter_range: FilterTimeRange
    ) -> Dict[str, str]:
        assert_filter_range(filter_range)
        gte_time, lte_time = filter_range.start, filter_range.end

        filter_string = f"{filter_param.name}"
        if gte_time:
            filter_string += " " + f"gte {gte_time}"
        if lte_time:
            filter_string += " " + f"lte {lte_time}"
        return {
            "filter": filter_string,
        }

    def get_list_endpoint(self, resource: Resource, query_dict: Dict[str, str]):
        return f"{self.env.BASEURL}/{resource.name}?{urlencode(query_dict)}"

    def get_single_endpoint(self, resource: Resource, resource_id: str):
        return f"{self.env.BASEURL}/{resource.name}/{resource_id}"

    async def make_request(self, url, headers):
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            async with session.get(url, headers=headers) as response:
                if not (200 <= response.status <= 299):
                    raise Exception(
                        "Error during sending events to Abnormal SOAR API. Response code: {}. Text:{}".format(
                            response.status, await response.text()
                        )
                    )
                await asyncio.sleep(1)
                return json.loads(await response.text())

    async def send_request(self, url) -> Dict[str, Any]:
        attempts = 1
        while True:
            try:
                response_data = await self.make_request(url, self.get_header())
            except Exception as e:
                if attempts < 3:
                    logging.warning(
                        f"Error while getting data from Abnormal Soar API. Attempt:{attempts} - URL: {url}",
                        exc_info=e,
                    )
                    await asyncio.sleep(3)
                    attempts += 1
                else:
                    logging.error(
                        "Abnormal Soar API request failed with error", exc_info=e
                    )
                    # TODO: Maybe raise an exception here and stop processing?
                    return {}
            else:
                return response_data

    async def generate_resource_ids(
        self,
        resource: Resource,
        filter_range: FilterTimeRange,
        output_queue,
        filter_param: FilterParam,
        post_processing_func=lambda x: [x],
    ):
        query_dict = self.get_query_params(filter_param, filter_range)
        nextPageNumber = 1
        while nextPageNumber:
            query_dict["pageNumber"] = nextPageNumber
            response_data = await self.send_request(
                self.get_list_endpoint(resource, query_dict)
            )
            total = response_data.get("total")

            assert (
                total is not None
            ), "short circuiting as total field is not present in the response"
            logging.info(f"Total number of {resource} is: {total}")

            # if not entity_date_set:
            #     self.set_date_on_entity(context, date_filter["lte_datetime"], self.MAP_RESOURCE_TO_ENTITY_VALUE[resource])

            for id in post_processing_func(response_data):
                await output_queue.put(id)

            nextPageNumber = int(response_data.get("nextPageNumber"))

            assert (
                nextPageNumber > 2
            ), "short circuting as we are fetching more than 2 pages"

    async def process_resource_ids(
        self,
        resource: Resource,
        input_queue: Queue,
        output_queue: Queue,
        post_processing_func=lambda x: [x],
    ):
        resource_log_type = MAP_RESOURCE_TO_LOGTYPE[resource]
        while True:
            current_id = await input_queue.get()
            if current_id is None:
                break
            try:
                response_data = await self.send_request(
                    self.get_single_endpoint(resource, current_id)
                )
                for output in post_processing_func(response_data):
                    await output_queue.put((resource_log_type, output))
            except Exception:
                logging.error(f"Discarding enqueued resource id: {current_id}")

            input_queue.task_done()


class AbnormalThreatsAPI(AbnromalSoarAPI):
    def extract_threat_messages(timerange: TimeRange):
        def callback(threat_resp: Dict):
            threat_id = threat_resp.get("threatId")

            ctx = {
                "threat_id": threat_id,
                "timerange": timerange,
            }

            filtered_messages = []
            for message in threat_resp.get("messages"):
                message_id = message.get("abxMessageId")
                remediation_time_str = message.get("remediationTimestamp")

                ctx = {
                    **ctx,
                    "message_id": message_id,
                    "remediation_time_str": remediation_time_str,
                }

                try:
                    remediation_time = datetime.strptime(
                        remediation_time_str, TIME_FORMAT_WITHMS
                    )
                    if (
                        remediation_time >= timerange.start
                        and remediation_time <= timerange.end
                    ):
                        filtered_messages.append(message)
                        logging.info(
                            f"Successfully processed message for threat: {ctx}"
                        )
                    else:
                        logging.warning(f"Skipped processing message for threat: {ctx}")
                except Exception as e:
                    logging.error(
                        f"Failed to process message for threat: {ctx} with error",
                        exc_info=e,
                    )

            return filtered_messages

        return callback

    def extract_threat_campaign_ids(threats_resp):
        return [threat.get("threatId") for threat in threats_resp.get("threats", [])]

    async def get_all_threat_messages(
        self, threats_date_filter: TimeRange, output_queue: Queue
    ):
        assert_time_range(threats_date_filter)

        intermediate_queue = asyncio.Queue()
        final_filter_time = TimeRange(
            threats_date_filter.start - self.env.LAG_ON_BACKEND,
            threats_date_filter.end - self.env.LAG_ON_BACKEND,
        )

        # Needs to be a synchronous operation from old interval -> new interval to avoid race conditions
        for filter_range in compute_intervals(
            timerange=threats_date_filter,
            outage_time=self.env.OUTAGE_TIME,
            frequency=self.env.FREQUENCY,
            lag_on_backend=self.env.LAG_ON_BACKEND,
        ):
            await asyncio.create_task(
                self.generate_resource_ids(
                    resource=Resource.threats,
                    filter_range=filter_range,
                    filter_param=FilterParam.latestTimeRemediated,
                    output_queue=intermediate_queue,
                    post_processing_func=lambda x: self.extract_threat_campaign_ids(x),
                ),
            )

        consumers = [
            asyncio.create_task(
                self.process_resource_ids(
                    resource=Resource.threats,
                    input_queue=intermediate_queue,
                    output_queue=output_queue,
                    post_processing_func=self.extract_threat_messages(
                        timerange=final_filter_time
                    ),
                )
            )
            for _ in range(self.env.NUM_CONCURRENCY)
        ]

        await intermediate_queue.join()
        await asyncio.gather(consumers)

        for c in consumers:
            c.cancel()


class AbnormalCaseAPI(AbnromalSoarAPI):
    def extract_case_ids(cases_resp):
        return [case.get("caseId") for case in cases_resp.get("cases", [])]

    async def get_all_cases(self, cases_date_filter: TimeRange, output_queue: Queue):
        assert_time_range(cases_date_filter)

        intermediate_queue = asyncio.Queue()

        # Needs to be a synchronous operation from old interval -> new interval to avoid race conditions
        for filter_range in compute_intervals(
            timerange=cases_date_filter,
            outage_time=self.env.OUTAGE_TIME,
            frequency=self.env.FREQUENCY,
            lag_on_backend=self.env.LAG_ON_BACKEND,
        ):
            await asyncio.create_task(
                self.generate_resource_ids(
                    resource=Resource.cases,
                    filter_range=filter_range,
                    filter_param=FilterParam.customerVisibleTime,
                    output_queue=intermediate_queue,
                    post_processing_func=lambda x: self.extract_case_ids(x),
                )
            )

        consumers = [
            asyncio.create_task(
                self.process_resource_ids(
                    resource=Resource.cases,
                    input_queue=intermediate_queue,
                    output_queue=output_queue,
                )
            )
            for _ in range(self.env.NUM_CONCURRENCY)
        ]

        await asyncio.gather(consumers)
        await intermediate_queue.join()

        for c in consumers:
            c.cancel()


# def set_date_on_entity(context, lte_datetime, entity_value):
#     datetimeEntityId = df.EntityId("SoarDatetimeEntity", "latestDatetime")
#     context.signal_entity(
#         datetimeEntityId, "set", {"type": entity_value, "date": lte_datetime}
#     )
