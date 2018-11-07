/*
 * RedisHelper.cpp
 *
 *  Created on: Aug 6, 2018
 *      Author: root
 */

#include "RedisHelper.h"

RedisHelper::RedisHelper(string addr, bool retry, bool sentinel, int conn_timeout, int rw_timeout):client_pub_(NULL),client_sub_(NULL),client_con_(NULL)
{
    addr_ = addr;
    retry_ = retry;
    sentinel_ = sentinel;
    conn_timeout_ = conn_timeout;
    rw_timeout_ = rw_timeout;
}

RedisHelper::~RedisHelper() {
	if(client_pub_ != NULL)
    {
        client_pub_->close();
        delete client_pub_;
        client_pub_ = NULL;
	}
	if(client_sub_ != NULL)
    {
        client_sub_->close();
        delete client_sub_;
        client_sub_ = NULL;
	}
}

bool RedisHelper::open()
{
    if(client_pub_ != NULL)
    {
        client_pub_->close();
        delete client_pub_;
        client_pub_ = NULL;
    }
    if(client_sub_ != NULL)
    {
        client_sub_->close();
        delete client_sub_;
        client_sub_ = NULL;
    }
    if(client_con_ != NULL)
    {
        client_con_->close();
        delete client_con_;
        client_con_ = NULL;
    }

    client_con_ = new  acl::redis_client(addr_.c_str(), conn_timeout_, rw_timeout_, retry_);
    client_pub_ = new  acl::redis_client(addr_.c_str(), conn_timeout_, rw_timeout_, retry_);
    client_sub_ = new  acl::redis_client(addr_.c_str(), conn_timeout_, rw_timeout_, retry_);


    redis_pub_.set_client(client_pub_);
    redis_sub_.set_client(client_sub_);

    return check_connect();
}

bool RedisHelper::check_connect()
{
    bool result = false;
    if(client_con_ == NULL)
        return result;

    acl::redis_connection redis_con(client_con_);         //client_pub_调用订阅函数之后就不能调用ping
    result = redis_con.ping();
    if(!result)
    {
        client_con_->close();
        delete client_con_;
        client_con_ = NULL;
    }
    return result;
}

bool RedisHelper::set(string key, string value)
{
	acl::redis redis(client_pub_);
	bool result = redis.set(key.c_str(), value.c_str());
	if(!result)
	{
		const acl::redis_result* res = redis.get_result();
		printf("error: %s\r\n",res ? res->get_error() : "unknown error");
	}

	return result;
}

int RedisHelper::publish(string channel, string message, string key)
{
	if(!key.empty())
	{
		set(key, message);
	}

	int result = redis_pub_.publish(channel.c_str(), message.c_str(), message.length());
	if(result < 0)
	{
		const acl::redis_result* res = redis_pub_.get_result();
        printf("error: %s\r\n",res ? res->get_error() : "unknown error");
	}
	return result;
}

int RedisHelper::publish(string channel, char* message, int length, string key)
{
	if(!key.empty())
	{
		set(key, message);
	}

	int result = redis_pub_.publish(channel.c_str(), message, length);
	return result;
}


int RedisHelper::subscribe(string channel, ...)
{
    int result = 0;
    va_list pArgs;
    va_start(pArgs, channel.c_str());
    const char* tmpChannel = channel.c_str();
    while(tmpChannel != NULL)
    {
       redis_sub_.clear();
       result = redis_sub_.subscribe(tmpChannel, NULL);
       if(result <= 0)
       {
           printf("subscribe %s error(%s), ret: %d\r\n",channel.c_str(), redis_sub_.result_error(), result);
       }
       tmpChannel = va_arg(pArgs, char*);
    }
    va_end(pArgs);
    return result;
}

int RedisHelper::unsubscribe(string channel)
{
    int result = redis_sub_.subscribe(channel.c_str(), NULL);
    if(result <= 0)
    {
        printf("subscribe %s error(%s), ret: %d\r\n",channel.c_str(), redis_sub_.result_error(), result);
    }
    return result;
}


bool RedisHelper::getMessage(string& message, string channel)
{
	acl::string acl_channel;
	acl::string acl_msg;

	redis_sub_.clear();
	bool result = redis_sub_.get_message(acl_channel, acl_msg);
	if(result == true && channel.empty())
	{
		message = acl_msg.c_str();
        //printf("get one message: %s, channel: %s\r\n",acl_msg.c_str(), acl_channel.c_str());
	}
	else if( result == true && strcmp(channel.c_str(), acl_channel.c_str()) == 0)
	{
		message = acl_msg.c_str();
	}
	return result;
}
