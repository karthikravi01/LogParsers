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
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)


def process_dlt_files(input_dir: Path, output_dir: Path) -> None:
    input_dir = input_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(input_dir.glob("*.dlt"))
    if not files:
        logger.warning("No .dlt files found in %s", str(input_dir))
        return

    for dlt_path in files:
        # Cn also use UUID or hash for unique naming (Need to Research)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_name = f"{dlt_path.stem}_{timestamp}.log"
        output_file = output_dir / out_name

        logger.info("Starting DLT conversion: %s → %s", str(dlt_path), str(output_file))

        count = 0
        try:
            with open(output_file, "w") as f:
                for msg in DltFileReader(str(dlt_path)):
                    f.write(str(msg) + "\n")
                    count += 1
        except Exception:
            logger.exception("Failed while processing DLT file %s", str(dlt_path))
            # continue to next file rather than aborting whole run if one fails
            continue

        logger.info("Finished processing %s. Messages written: %d", dlt_path.name, count)


if __name__ == "__main__":
    base = Path(__file__).parent
    input_dir = base / "input"
    output_dir = base / "output"

    if not input_dir.exists():
        logger.error("Input directory does not exist: %s", str(input_dir))
        sys.exit(1)

    process_dlt_files(input_dir, output_dir)




