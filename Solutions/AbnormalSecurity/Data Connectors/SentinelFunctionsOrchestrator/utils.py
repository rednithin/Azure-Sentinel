from datetime import datetime, timedelta
from typing import NamedTuple
from enum import Enum
from typing import List, TypedDict
import os

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
TIME_FORMAT_WITHMS = "%Y-%m-%dT%H:%M:%S.%fZ"

def try_str_to_datetime(time: str) -> datetime:
    try:
        return datetime.strptime(time, TIME_FORMAT)
    except Exception as _:
        pass
    return datetime.strptime(time, TIME_FORMAT_WITHMS)


class TimeRange(NamedTuple):
    start: datetime
    end: datetime


class FilterTimeRange(NamedTuple):
    start: datetime
    end: datetime | None


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

def assert_time_range(t: TimeRange):
    assert all(isinstance(x, datetime) for x in [t.start, t.end])
    assert t.end > t.start

def assert_filter_range(t: FilterTimeRange):
    assert isinstance(t.start, datetime), f"invalid filter_range {t}"
    assert t.end is None or isinstance(
        t.end, datetime
    ), f"invalid filter_range {t}"
    assert t.end is None or (
        t.end >= t.start
    ), f"invalid filter_range {t}"


def compute_intervals(timerange: TimeRange, outage_time: timedelta, lag_on_backend: timedelta, frequency: timedelta) -> List[FilterTimeRange]:
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
    start_time, current_time = timerange.start, timerange.end
    print(f"Specified timerange: {timerange}")

    if current_time - start_time > outage_time:
        start_time = current_time - outage_time

    assert current_time - start_time <= outage_time

    start = start_time.replace() - lag_on_backend
    current = current_time.replace()

    print(f"Modified timerange: {timerange}")

    assert current > start

    limit = frequency
    add = frequency

    assert limit >= add

    intervals: List[FilterTimeRange] = []
    while current - start > limit:
        intervals.append(FilterTimeRange(start, start + add))
        start = start + add

    intervals.append(FilterTimeRange(start, None))

    return intervals

class EnvVariables(TypedDict):
    LAG_ON_BACKEND: timedelta
    OUTAGE_TIME: timedelta
    FREQUENCY: timedelta
    NUM_CONCURRENCY: int
    BASEURL: str
    API_TOKEN: str

def get_env_variables() -> EnvVariables:
    BASE_URL = os.environ.get("API_HOST", "https://api.abnormalplatform.com/v1")
    API_TOKEN = os.environ['ABNORMAL_SECURITY_REST_API_TOKEN']
    LAG_ON_BACKEND = timedelta(seconds=int(os.environ.get("LAG_ON_BACKEND", "30")))
    OUTAGE_TIME = timedelta(minutes=int(os.environ.get("OUTAGE_TIME", "15")))
    NUM_CONCURRENCY = int(os.environ.get("NUM_CONCURRENCY", "10"))
    FREQUENCY = timedelta(minutes=5)

    return EnvVariables(
        LAG_ON_BACKEND=LAG_ON_BACKEND,
        OUTAGE_TIME=OUTAGE_TIME,
        NUM_CONCURRENCY=NUM_CONCURRENCY,
        FREQUENCY=FREQUENCY,
        BASE_URL=BASE_URL,
        API_TOKEN=API_TOKEN,
    )