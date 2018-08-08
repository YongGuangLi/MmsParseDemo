/*
 * ConfigIni.h
 *
 *  Created on: Jul 25, 2018
 *      Author: root
 */

#ifndef CONFIGINI_H_
#define CONFIGINI_H_

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

using namespace boost::property_tree;

#include <string>
#include <iostream>

using namespace std;

class ConfigIni {
public:
	ConfigIni();
	bool initConfig(string);
	virtual ~ConfigIni();
};

#endif /* CONFIGINI_H_ */
