# NDISaster: Tool for Analyzing NDIS Drivers

The project consists of three files:

1. NDISaster.py - An IDA Python script
2. raw_packet.c - C program to generate raw packets (to be used as basis for fuzzer)
3. ndis_bd_5.h - Header file that will need to be parsed by IDA Pro before running the Python script (IDA doesn't have complete types for NDIS drivers)

The solution works by first identifying the relevant callback functions in an NDIS driver, then by generating a Windbg script and using it to trace code execution and identify relevant functions.

Usage:

1. Parse ndis_bd_5.h in IDA (use "Parse C Header File")

2. Run NDISaster.py in IDA (use "Run Python script")

3. After running the script, you should see that the main callback functions have been identified by IDA

4. Generate a Windbg script by calling this function from the IDA terminal: generate_windbg_packet_trace_script(driver_name, function_to_start_hooking_from, output_script_name, fuzzing_mode)

  Example: generate_windbg_packet_trace_script("bdfndisf", "Pr_ReceivePacketHandler", "C:\\NDISaster\\output", 0)
  
5. Run the generated script in Windbg when it is debugging the target machine. Steps:

  a. Open the log to save the trace: .logopen <path>
  
  b. Use this command to run the code: $$><script_name
  
  c. Generate some traffic to the target machine
  
  d. Close the log when you are done tracing: .logclose
  
6. Back in IDA, call this function: import_windbg_packet_trace(<logfile_name>)

7. You will see the functions in the disassembly tagged and named as per the protocol they are supposed to handle
