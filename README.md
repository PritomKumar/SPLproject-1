# Text Bandit

This program is used to steal data from open HTTP connection in any network. We just need to be present in the network to steal it!
Working procedures:
1. First the pcapCapture.cpp is called to capture the data in an open HTTP connection. It captures all the packets sending and receving in the connection. Then it writes all the packets in a user-specified file.
2. After caputuring the files the pcapAnalyze.cpp is called. It analyzes the packets gathers all the packets from the same connection in order. Then we can save the result in a user-specfied file and see the results. Thus the steal is complete!
