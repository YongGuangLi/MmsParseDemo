/*
 * RedisHelper.cpp
 *
 *  Created on: Aug 6, 2018
 *      Author: root
 */

#include "RedisHelper.h"

RedisHelper::RedisHelper(string addr, bool retry, bool sentinel, int conn_timeout, int rw_timeout) {
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
    client_pub_ = new  acl::redis_client(addr_.c_str(), conn_timeout_, rw_timeout_, retry_);
    client_sub_ = new  acl::redis_client(addr_.c_str(), conn_timeout_, rw_timeout_, retry_);

    redis_pub_.set_client(client_pub_);
    redis_sub_.set_client(client_sub_);

    return check_connect();
}

bool RedisHelper::check_connect()
{
    if(client_pub_ == NULL)
        return false;

    acl::redis_connection redis(client_pub_);
    bool result = redis.ping();
    if(result == false)
    {
        client_pub_->close();
        delete client_pub_;
        client_pub_ = NULL;

        client_sub_->close();
        delete client_sub_;
        client_sub_ = NULL;
    }

    return result;
}

bool RedisHelper::set(string key, string value)
{
	if(!check_connect())
		return false;

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
	if(!check_connect())
		return false;

	if(!key.empty())
	{
		set(key, message);
	}

	redis_pub_.clear();
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
	if(!check_connect())
		return false;

	if(!key.empty())
	{
		set(key, message);
	}

	redis_pub_.clear();
	int result = redis_pub_.publish(channel.c_str(), message, length);
	return result;
}

int RedisHelper::subscribe(string channel)
{
	redis_sub_.clear();
	int result = redis_sub_.subscribe(channel.c_str(), NULL);
	if(result <= 0)
	{
		printf("subscribe %s error(%s), ret: %d\r\n",channel.c_str(),redis_sub_.result_error(), result);
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
