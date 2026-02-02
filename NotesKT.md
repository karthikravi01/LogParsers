

## SD Vehicle Architecture Notes

### SPA – 2 Platform

#### SGA (Security)

* Responsible for vehicle **security**, all the things enter through here acts like a gateway.

#### HPA (High Performance ECU)

* Acts as the **brain** of the vehicle
* Handles **high-performance processing**
* Uses an **NVIDIA chip**
* Runs a **hypervisor** with **multiple virtual machines (VMs)**

  * One VM runs **Volvo software** on **QNX operating system**
* Software stack includes:

  * NVIDIA platform
  * Volvo platform
  * Volvo application software
* **NVIDIA provides middleware**
* Typically **2 virtual machines**
* Supports:

  * **Drive update functionality**
  * **Volvo software updates**

#### Safety & Hardware Control

* **ASIL B** – highest safety level mentioned
* **Hardware Control**

  * **HIA** and **HIB**
  * High Integrity A & B
  * Safety-related software for the **entire car system**
* **AUTOSAR**

  * Standardized software architecture
  * HIA and HIB are **AUTOSAR nodes**
  * Do **not output logs** (act like a **black box**)

#### Programming & Updates

* **Programming sessions** are used to perform updates

#### LPA (Low Power ECU)

* Low-power controller
* Receives signals
* Used to **reduce battery consumption**

#### VES

* Network **switch**
* Handles **network traffic**
* Manages vehicle networking

#### VIU (Vehicle Interface Unit)

* **Gateway ECU** (not shown in some diagrams)
* Acts as a gateway **between ECUs**
* Handles communication between ECUs
* Supports protocols like:

  * CAN
  * LIN
  * Ethernet
* Enables ECU-to-ECU communication

---

### SPA – 3 Platform

* **VIU is replaced by Zone Controllers**
* Zone controllers:

  * Reduce system complexity
  * Save **a lot of electrical wiring**
  * Improve overall architecture efficiency

---

### Query for data collection

project in ("ART High Performance Platform", "ART Central Execution Environment") AND status = closed AND type = "Fault Report" ORDER BY lastViewed DESC
 
---