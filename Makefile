LIBIEC_HOME=..

PROJECT_BINARY_NAME = MmsParse

#C,CC或CPP文件的后缀  
PS=cpp   

PROJECT_SOURCES = $(wildcard *.$(PS)) 
PROJECT_OBJS = $(patsubst %.$(PS),%.o,$(PROJECT_SOURCES))  
PROJECT_DEPS = $(patsubst %.o,%.d,$(PROJECT_OBJS))  
  
include $(LIBIEC_HOME)/make/target_system.mk
include $(LIBIEC_HOME)/make/stack_includes.mk

BOOST_INCLUDE = ../third_party/boost/include
PCAP_INCLUDE = ../third_party/libpcap/include
LOG_INCLUDE = ../third_party/log4cplus/include
#MYSQL_INCLUDE = ../third_party/mysql-5.1.52/include
PROTOBUF_INCLUDE = ../third_party/protobuf-3.3.0/include
ACL_INCLUDE= ../third_party/libacl/include
XML_INCLUDE = ../third_party/tinyXml/include

INCLUDES += -I$(BOOST_INCLUDE)
INCLUDES += -I$(PCAP_INCLUDE)
INCLUDES += -I$(LOG_INCLUDE)
#INCLUDES += -I$(MYSQL_INCLUDE)
INCLUDES += -I$(PROTOBUF_INCLUDE)
INCLUDES += -I$(ACL_INCLUDE) 
INCLUDES += -I$(XML_INCLUDE)

BOOST_SYSTEM_LIB = ../third_party/boost/lib/libboost_system.a
BOOST_FILESYSTEM_LIB = ../third_party/boost/lib/libboost_filesystem.a
BOOST_REGEX_LIB =  ../third_party/boost/lib/libboost_regex.a
BOOST_THREAD_LIB =  ../third_party/boost/lib/libboost_thread.a 
BOOST_DATETIME_LIB =  ../third_party/boost/lib/libboost_date_time.a
XML_LIB =  ../third_party/tinyXml/lib/libtinyxml.a
PCAP_LIB = ../third_party/libpcap/lib/libpcap.a 
LOG_LIB = ../third_party/log4cplus/lib/liblog4cplus.a 
#MYSQL_LIB = ../third_party/mysql-5.1.52/lib/libmysqlclient.a 
PROTOBUF_LIB = ../third_party/protobuf-3.3.0/lib/libprotobuf-lite.a 
ACL_CPP_LIB = ../third_party/libacl/lib/libacl_cpp.a
ACL_LIB = ../third_party/libacl/lib/libacl.a

LDLIBS += -lm -ldl -lrt   

all: $(PROJECT_BINARY_NAME)

include $(LIBIEC_HOME)/make/common_targets.mk

$(PROJECT_BINARY_NAME):	$(PROJECT_OBJS)
	$(CPP) $(CPPFLAGS) $(LDFLAGS) -o $(PROJECT_BINARY_NAME) -g $(PROJECT_OBJS) $(INCLUDES) $(LIB_NAME) $(PROTOBUF_LIB) $(PCAP_LIB) $(LOG_LIB) $(XML_LIB) $(BOOST_SYSTEM_LIB) $(BOOST_FILESYSTEM_LIB) $(BOOST_REGEX_LIB) $(BOOST_THREAD_LIB) $(BOOST_DATETIME_LIB) $(ACL_CPP_LIB) $(ACL_LIB) $(LDLIBS)  
 

clean:
	rm -f $(PROJECT_BINARY_NAME)
