<<<<<<< HEAD
# Multi-Agent AI Security Operations Center (SOC)
## Real-Time Threat Detection Pipeline

### Stage 8A: Real-Time Event Stream Testing
This project integrates a **continuous, near-real-time event-stream simulator** natively replaying historical network-flow records, allowing local end-to-end framework validations without integrating live hardware network-tap architectures.

> [!NOTE]
> The current infrastructure relies purely on the continuous interval injection of pre-parsed records to trigger analytical detection nodes sequentially. 
> - **It is NOT natively intercepting Live Packet traffic via PCAP taps/Wireshark.**
> - **It DOES NOT depend upon an explicit network Kafka Broker running locally globally across the machine.** 

### Local Wrapper Workflow (Producer/Consumer IPC Execution)
Because the background transport natively utilizes Python's memory `queue.Queue()`, creating terminal persistence scaling directly requires launching both modules inside identical node thresholds (Same-Process).
You natively launch both boundaries via the `realtime_wrapper.py`.

#### 1. Terminate External Python Backgrounds
Ensure all old testing environments are flushed cleanly. 

#### 2. Launch Wrapper Loop (Terminal 1)
```powershell
python kafka/realtime_wrapper.py --interval 0.5 --loop --continuous --balanced
```
*(The `--interval` metric denotes artificial delay injected between DB rows cleanly enabling testing execution limits naturally mimicking streams. Ctrl+C stops this process efficiently).* 

#### 3. Monitor SQLite Storage Limits (Terminal 2)
On a separate independent CLI endpoint natively evaluating limits, you can poll generated metrics accurately mapping downstream pipeline scaling:
```powershell
python query_incidents.py --summary 
python query_alerts.py --summary
```

### Producer CLI Configuration Bounds (Fallback Native Modes)
If you are evaluating explicit subsets testing components dynamically, `realtime_producer.py` respects these attributes dynamically:
- `--interval FLOAT`: Artificial seconds delayed between injection boundaries natively (Default: 1.0)
- `--count INTEGER`: Explicit event capping before graceful exit triggers locally.
- `--continuous`: Force unbounded infinite execution natively unless implicitly explicitly limited by counts correctly. 
- `--loop`: Restart execution streams upon dataset EOF boundary triggers globally allowing endless persistence evaluations locally.
- `--label`: Filter explicit dataset limits testing model architectures uniquely (`"benign"`, `"attack"`, `"all"`).

#### Known Constraints
Since this is natively lab-scaled architecture mocking PCAP intercepts, the underlying bounds do not scale appropriately against >500 GB massive raw logs mapping high velocity architectures. Real-time implementation metrics mapped directly to `interval` timings rely explicitly on Pandas chunk extraction methodologies.
=======
# Multi-AI-Agent-in-SOC-for-Real-Time-Threat-Detection
>>>>>>> fa080a8abfa850e4f66a49b71038e827638980fc
