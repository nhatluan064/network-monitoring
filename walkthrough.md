# Network Monitor App Walkthrough

## Overview
This application is a lightweight network monitoring tool designed to help IT administrators track internal network usage. It captures DNS queries to identify which websites are being visited by internal IP addresses.

## Features
-   **Real-time Monitoring**: Displays visited websites instantly as they are accessed.
-   **Resolved IP**: Shows the actual IP address of the visited website.
-   **IP Connection Monitor**: Tracks all TCP/UDP connections between IPs.
-   **Suspicious Activity Detection**: Automatically highlights entertainment, gaming, and betting sites.
-   **Target Filtering**: Filter traffic by a specific Source IP to track a single user.
-   **Lightweight**: Uses DNS sniffing and packet summary.

## How to Run
1.  Open a terminal as **Administrator**.
2.  Navigate to the project folder:
    ```powershell
    cd d:\Developer\NetworkMonitor
    ```
3.  Run the application:
    ```powershell
    python main.py
    ```
4.  Open your web browser and go to: [http://localhost:5000](http://localhost:5000)
5.  **Select Network Interface**: Choose the active network card (WiFi or Ethernet) from the dropdown list.
6.  **Click Start**: Press the "Start Monitoring" button to begin capturing traffic.
7.  **Switch Views**: Use the tabs to switch between "Website Monitor" (DNS) and "IP Connections".
8.  **Filter**: Enter a specific IP (e.g., `10.10.85.87`) in the filter box to see only that machine's traffic.

## How to Deploy Agent (Automated)
To monitor other computers:

1.  **Prepare the Files**:
    -   On your IT machine, open `setup.bat` with Notepad.
    -   Edit the line `set "SERVER_IP=10.10.85.3"` to match your actual IP.
    -   Copy these 3 files to a USB or Shared Folder:
        -   `agent.py`
        -   `setup.bat`
        -   `requirements.txt` (optional, script installs manually but good to have)

2.  **Install on Employee Machine**:
    -   Copy the files to a folder (e.g., `C:\NetworkMonitor`).
    -   Right-click `setup.bat` -> **Run as Administrator**.
    -   Wait for it to finish. It will:
        -   Install Python (if missing).
        -   Install libraries.
        -   Configure the IP.
        -   Start the agent.
        -   Add to Startup.

3.  **Done!** The agent is now running and will auto-start on reboot.

## Troubleshooting
-   **No Data Appearing?**
    -   Ensure you selected the correct **Network Interface**. Try different ones if unsure.
    -   Ensure you have **Npcap** installed (usually comes with Wireshark).
    -   Ensure you are running the terminal as **Administrator**.
    -   If you are on a switched network, you may only see your own traffic. To see others, this tool needs to be running on a Gateway, Proxy, or a port-mirrored switch port.
