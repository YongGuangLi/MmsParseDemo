/*
 * PcapFileManager.cpp
 *
 *  Created on: Jul 2, 2018
 *      Author: root
 */

#include "PcapDirManager.h"

PcapDirManager::PcapDirManager(string dirName)
{
	dirName_ = dirName;
}

PcapDirManager::~PcapDirManager() {
	// TODO Auto-generated destructor stub
}

void PcapDirManager::searchPacpFile()
{
	mapLastWriteFile_.clear();

	boost::regex reg(SEARCHREGEX);

	boost::filesystem::path file_path(dirName_);   //初始化
	boost::filesystem::directory_iterator itFile(file_path);
	boost::filesystem::directory_iterator end_iter; // 缺省构造生成一个结束迭代器
	for (; itFile != end_iter; ++itFile)
	{
		if (boost::filesystem::is_regular_file(*itFile))
		{
			if(boost::regex_match( itFile->path().string() , reg))
			{
				mapLastWriteFile_.insert( make_pair( last_write_time(itFile->path()), itFile->path().string() ));
			}
		}
	}
}

string PcapDirManager::getFisrtFile()
{
	searchPacpFile();

	string fileName;
	map<time_t, string>::iterator it = mapLastWriteFile_.begin();
	if(it != mapLastWriteFile_.end())
		fileName = it->second;
	return fileName;
}

int PcapDirManager::getFileNum()
{
	searchPacpFile();          //重新搜索路径下文件
	int iSize = mapLastWriteFile_.size();
	return iSize;
}

void PcapDirManager::renamePcapFile(string oldFile, string newFile)
{
	boost::filesystem::path filePath(newFile);
	if(!boost::filesystem::exists(filePath.parent_path()))         //如果不存在，则创建
	{
		boost::filesystem::create_directory(filePath.parent_path());
	}

	boost::filesystem::rename(oldFile, newFile);
	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "move " + oldFile + " to " + newFile);
}
