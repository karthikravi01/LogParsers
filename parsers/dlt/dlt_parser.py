"""from dlt import DltReader

with DltReader("example.dlt") as r:
    for storage_header, packet in r:
        if not packet.has_payload():
            # skip packets that do not have a payload
            continue

        print(packet)
        """


        
import logging
from pydlt import DltFileReader
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)
# TODO : can be switched to UUID(need to check)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S") 


input_file = "./input/TCA_ECU1_UXC_HPA_SGA_DHU_2026-01-20T14_18-17.592161Z.dlt"
Path("output").mkdir(exist_ok=True)
output_file = f"output/dlt_{timestamp}.log"

logger.info("Starting DLT conversion: %s → %s", input_file, output_file)

count = 0

try:
    with open(output_file, "w") as f:
        for msg in DltFileReader(input_file):
            f.write(str(msg) + "\n")
            count += 1
except Exception:
    logger.exception("Failed while processing DLT file")
    raise

logger.info("Finished processing. Messages written: %d", count)




