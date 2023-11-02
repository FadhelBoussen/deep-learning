# enhancing attack detection through artificial intelligence
Our solution is to design a real-time attack detection system, The first step is to analyze the network using cicflowmeter which will generate a csv file containing the analysis results that will later serve as attributes for the deep learning model, then we will retrieve and send this data as a flowfile to apache kafka using apache nifi with the adequate processors.
Once the data is sent to apache kafka it can be retrieved with kafka consumer in jupyter notebook using topic name and IP address and finally real-time detection using the deep learning algorithm ANN. 
# about the Database 
CICDS2017 is a database developed by the Canadian Research Institute for Cyber Security, consisting of benign traffic and the most common attacks based on the 2016 McAfee report (DOS, DDOS, Web-based, Brute force..). including different operating systems (Windows, Ubuntu, MACOS X) and network devices (modems, switches, firewalls, routers).
It also includes the results of network traffic analysis using CICFlowMeter with tagged streams based, source and destination IP addresses, source and destination ports, protocols and attacks, this database is presented as a csv file
# network analyser (cicflowmeter) 
CICFlowmeter-V4.0 (formerly known as ISCXFlowMeter) is a network traffic flow generator and analyzer for anomaly detection. It has been used in many cybersecurity datasets such as Android Adware-General Malware dataset (CICAAGM2017), IPS/IDS dataset (CICIDS2017), Android Malware dataset (CICAndMal2017).
cicflowmeter was developed by "Arash Habibi Lashkari" researcher and developer in cic (Canadian Institute for Cybersecurity).
# architecture: 
below the solution architecture that describes the detection process:

   ╔═══════════════╗       ╔══════╗       ╔══════╗
   ║ Ciclowmeter ║ ----► ║ NiFi ║ ----► ║ Kafka ║
   ╚═══════════════╝       ╚══════╝       ╚══════╝
                                          │
                                          ▼
                        ╔═════════════════════════╗
                        ║ Deep Learning Model   ║
                        ╚═════════════════════════╝
