/* 
 *  Copyright (c) 2015, nexGIN, RC.
 *  All rights reserved.
 * 
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "BrokerConnectionManager.h"




BrokerConnectionManager::BrokerConnectionManager(std::string HostName,
        std::string btp,int bport)
{
    //initialize broker API
    broker::init();
    this->b_port = bport;
    this->connected = false;
    //local host object
    this->ptlocalhost = new broker::endpoint(HostName);
    // broker messages queue
    this->ptmq = new broker::message_queue(btp,*ptlocalhost);
    // pooling for message queue
    ptpfd = new pollfd{this->ptmq->fd(), POLLIN, 0};
    // Query Manager Object
    this->qm = new BrokerQueryManager(ptlocalhost,ptmq,&btp);
}

BrokerConnectionManager::~BrokerConnectionManager()
{
    // query manager object deletion
    delete this->qm;
    //local host object deletion
    delete this->ptlocalhost;
    // pooling object linked with message queue deletion
    delete this->ptpfd;
    // message queue deletion
    delete this->ptmq;
}

bool BrokerConnectionManager::listenForBrokerConnection()
{
    std::cout<<"listening for new Connection"<<std::endl;
    this->connected = false;
    //listen for new connection. wait untill at-least one connection is found
    ptlocalhost->listen(b_port,qm->getLocalHostIp().c_str());
    //pop new connection request
    auto conn_status = 
    this->ptlocalhost->incoming_connection_status().need_pop();
    for(auto cs: conn_status)
    {
        if(cs.status == broker::incoming_connection_status::tag::established)
        {
            std::cout<<"Connection Established"<<std::endl;
            this->connected = true;
            break;
        }
    }
    return this->connected;
}


bool BrokerConnectionManager::getAndProcessQuery()
{
    //get queries form message queue
    bool temp = qm->getQueriesFromBrokerMessage(this->ptpfd,connected);
    //if success
    if(temp)
    {
        //then extract columns form query strings
      temp = qm->queryColumnExtractor();
    }
    // extract event add/removed form event part if success
    if(qm->getEventsFromBrokerMessage())
    {
        // then fill the out_query_vector with query data
        temp = qm->queryDataResultVectorInit();
    }
    return temp;
}

void BrokerConnectionManager::trackChangeAndSendResponseToMaster()
{
    qm->queriesUpdateTrackingHandler();
}



bool BrokerConnectionManager::isConnectionAlive()
{
    //check connection queue if there is update
    auto conn_status =
    this->ptlocalhost->incoming_connection_status().want_pop();
    for(auto cs: conn_status)
    {
        // if connection object found the check if there is disconnect flag
        if(cs.status == broker::incoming_connection_status::tag::disconnected)
        {
            //if disconnected then break the connection.
            std::cout<<"Connection Broken"<<std::endl;
            this->connected = false;
            return true;
        }
    }
    return this->connected;
}

 
BrokerQueryManager* BrokerConnectionManager::getQueryManagerPointer()
{
    return this->qm;
}
