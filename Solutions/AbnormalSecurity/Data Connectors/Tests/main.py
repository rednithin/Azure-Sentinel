import logging
import os
import asyncio
import time
from datetime import datetime, timedelta
from ..SentinelFunctionsOrchestrator.soar_connector_async_v2 import get_cases, get_threats
from ..SentinelFunctionsOrchestrator.utils import get_context, TIME_FORMAT

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
            logging.info(
                f"Filtering messages in range {ctx.CLIENT_FILTER_TIME_RANGE.start} : {ctx.CLIENT_FILTER_TIME_RANGE.end}"
            )
            asyncio.run(get_threats(ctx=ctx, output_queue=output_queue))

            stored_time = ctx.CURRENT_TIME
            logging.info(f"Sleeping for {ctx.FREQUENCY.total_seconds()} seconds\n\n")
            time.sleep(ctx.FREQUENCY.total_seconds())

    except KeyboardInterrupt:
        pass

    idlist = []
    while not output_queue.empty():
        current = output_queue.get_nowait()
        print(current)
        idlist.append(current[1]["abxMessageId"])

    idset = set(idlist)
    maxid = max(idlist)
    duplicates = find_duplicates(idlist)
    missedids = list(filter(lambda x: x not in idset, list(range(1, maxid + 1))))

    print("\n\n\nSummary of the operation")

    print("Ingested values", idlist)
    print(f"Max ID: {maxid}")
    print(f"Duplicates: {duplicates}")
    print(f"Missed IDs: {missedids}")

    assert len(idset) == len(idlist), "Duplicates exist"
    assert len(duplicates) == 0, "There are duplicates"
    assert len(missedids) == 0, "There are missed IDs"
