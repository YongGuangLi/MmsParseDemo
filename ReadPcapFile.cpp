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
		LOG_DEBUG(errbuf_);
		renamePcapFile(filePath, "/home/test/move/1231.txt");
	}
	return result;
}

void ReadPcapFile::renamePcapFile(string oldFile, string newFile)
{
	boost::filesystem::path filePath(newFile);
	if(!boost::filesystem::exists(filePath.parent_path()))         //如果不存在，则创建
	{
		boost::filesystem::create_directory(filePath.parent_path());
	}

	boost::filesystem::rename(oldFile, newFile);
	LOG_DEBUG(string("move ").append(oldFile).append(" to ").append(newFile));
}

int ReadPcapFile::pcapNextEx(struct pcap_pkthdr ** pkthdr, const u_char ** dataBuf)
{
	int result = pcap_next_ex(fp_, pkthdr, dataBuf);
	return result;
}
