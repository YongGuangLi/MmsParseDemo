/*
 * PcapFileManager.h
 *
 *  Created on: Jul 2, 2018
 *      Author: root
 */

#ifndef PCAPDIRMANAGER_H_
#define PCAPDIRMANAGER_H_

#include "Log4Cplus.h"

#include <boost/filesystem.hpp>
#include <boost/regex.hpp>
#include <string>
#include <map>

using namespace std;
//using namespace boost::filesystem;       //需要屏蔽，不然会和protubuf冲突


#define SEARCHREGEX "^.*[0-9]{14}\\.pcap$"

class PcapDirManager {
public:
	PcapDirManager(string dirName);
	virtual ~PcapDirManager();

	void searchPacpFile();     //搜索路径下文件

	boost::filesystem::path getFisrtFile();    //获取修改时间最早的文件

	int getFileNum();        //返回文件个数

	void renamePcapFile(string oldFile, string newFile);
private:
	map<time_t, boost::filesystem::path> mapLastWriteFile_;       //按最后修改时间把文件排序
	string dirName_;
};

#endif /* PCAPFILEMANAGER_H_ */
