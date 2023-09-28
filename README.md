# deep-learning
Our solution is to design a real-time attack detection system, The first step is to analyze the network using cicflowmeter which will generate a csv file containing the analysis results that will later serve as attributes for the deep learning model, then we will retrieve and send this data as a flowfile to apache kafka using apache nifi with the adequate processors.
Once the data is sent to apache kafka it can be retrieved with kafka consumer in jupyter notebook using topic name and IP address and finally real-time detection using the deep learning algorithm ANN.


![image](https://github.com/FadhelBoussen/deep-learning/assets/144439317/4d2b8949-9f24-4b09-9a26-257e060041a6)
