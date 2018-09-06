/*
 * ReadPcapFile.cpp
 *
 *  Created on: Jul 2, 2018
 *      Author: root
 */

#include "ReadPcapFile.h"

ReadPcapFile::ReadPcapFile() {
	// TODO Auto-generated constructor stub

}

ReadPcapFile::~ReadPcapFile() {
	// TODO Auto-generated destructor stub
}

bool ReadPcapFile::openPcapFile(string filePath)
{
	bool result = true;
	if((fp_ = pcap_open_offline(filePath.c_str(), errbuf_) ) == NULL)
	{
		result = false;
	}
	return result;
}


int ReadPcapFile::pcapNextEx(struct pcap_pkthdr ** pkthdr, const u_char ** dataBuf)
{
	int result = pcap_next_ex(fp_, pkthdr, dataBuf);
	return result;
}
