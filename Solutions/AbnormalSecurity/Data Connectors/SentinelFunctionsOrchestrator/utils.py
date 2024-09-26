from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional
import os
from pydantic import BaseModel, model_validator

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
TIME_FORMAT_WITHMS = "%Y-%m-%dT%H:%M:%S.%fZ"

def try_str_to_datetime(time: str) -> datetime:
    try:
        return datetime.strptime(time, TIME_FORMAT)
    except Exception as _:
        pass
    return datetime.strptime(time, TIME_FORMAT_WITHMS)


class TimeRange(BaseModel):
    start: datetime
    end: datetime

    @model_validator(mode='before')
    def check_start_less_than_end(cls, values):
        start = values.get('start')
        end = values.get('end')
        
        if start > end:
            raise ValueError(f'Start time {start} is greater then end time {end}')
        return values


class OptionalEndTimeRange(BaseModel):
    start: datetime
    end: Optional[datetime]

    @model_validator(mode='before')
    def check_start_less_than_end(cls, values):
        start = values.get('start')
        end = values.get('end')
        
        if end is not None and start > end:
            raise ValueError(f'Start time {start} is greater then end time {end}')
        return values


class Context(BaseModel):
    LAG_ON_BACKEND: timedelta
    OUTAGE_TIME: timedelta
    FREQUENCY: timedelta
    NUM_CONCURRENCY: int
    MAX_PAGE_NUMBER: int
    BASE_URL: str
    API_TOKEN: str
    TIME_RANGE: TimeRange
    CLIENT_FILTER_TIME_RANGE: TimeRange

class Resource(Enum):
    threats = 0
    cases = 1


class FilterParam(Enum):
    receivedTime = 0
    createdTime = 1
    firstObserved = 2
    latestTimeRemediated = 3
    customerVisibleTime = 4


MAP_RESOURCE_TO_LOGTYPE = {
    Resource.threats: "ABNORMAL_THREAT_MESSAGES",
    Resource.cases: "ABNORMAL_CASES",
}

MAP_RESOURCE_TO_ENTITY_VALUE = {
    Resource.threats: "threats_date",
    Resource.cases: "cases_date",
}

def compute_intervals(ctx: Context) -> List[OptionalEndTimeRange]:
    """
    Function that returns for a time range [X, Y]
    It returns an array of intervals of frequency size by accounting for lag_on_backend and outage_time.
    timerange.start must be greater than 15 mins
    [
        [X - lag_on_backend, X - lag_on_backend + 5]
        ...
        [Z, None]
    ]
    """
    timerange = ctx.TIME_RANGE
    
    start_time, current_time = timerange.start, timerange.end
    print(f"Specified timerange: {timerange}")

    if current_time - start_time > ctx.OUTAGE_TIME:
        start_time = current_time - ctx.OUTAGE_TIME

    assert current_time - start_time <= ctx.OUTAGE_TIME

    start = start_time.replace() - ctx.LAG_ON_BACKEND
    current = current_time.replace()

    print(f"Modified timerange: {timerange}")

    assert current > start

    limit = ctx.FREQUENCY
    add = ctx.FREQUENCY

    assert limit >= add

    intervals: List[OptionalEndTimeRange] = []
    while current - start > limit:
        intervals.append(OptionalEndTimeRange(start=start, end=start + add))
        start = start + add

    intervals.append(OptionalEndTimeRange(start=start, end=None))

    return intervals



def get_context(stored_date_time: str) -> Context:
    BASE_URL = os.environ.get("API_HOST", "https://api.abnormalplatform.com/v1")
    API_TOKEN = os.environ['ABNORMAL_SECURITY_REST_API_TOKEN']
    LAG_ON_BACKEND = timedelta(seconds=int(os.environ.get("LAG_ON_BACKEND", "30")))
    OUTAGE_TIME = timedelta(minutes=int(os.environ.get("OUTAGE_TIME", "15")))
    NUM_CONCURRENCY = int(os.environ.get("NUM_CONCURRENCY", "10"))
    MAX_PAGE_NUMBER = int(os.environ.get("MAX_PAGE_NUMBER", "3"))
    FREQUENCY = timedelta(minutes=5)
    
    STORED_TIME = try_str_to_datetime(stored_date_time)
    CURRENT_TIME = datetime.now()
    TIME_RANGE = TimeRange(start=STORED_TIME, end=CURRENT_TIME)
    CLIENT_FILTER_TIME_RANGE = TimeRange(start=STORED_TIME - LAG_ON_BACKEND, end=CURRENT_TIME - LAG_ON_BACKEND)

    return Context(
        LAG_ON_BACKEND=LAG_ON_BACKEND,
        OUTAGE_TIME=OUTAGE_TIME,
        NUM_CONCURRENCY=NUM_CONCURRENCY,
        FREQUENCY=FREQUENCY,
        BASE_URL=BASE_URL,
        API_TOKEN=API_TOKEN,
        TIME_RANGE=TIME_RANGE,
        CLIENT_FILTER_TIME_RANGE=CLIENT_FILTER_TIME_RANGE,
        MAX_PAGE_NUMBER=MAX_PAGE_NUMBER
    )