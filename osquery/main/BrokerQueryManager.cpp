/* 
 *  Copyright (c) 2015, nexGIN, RC.
 *  All rights reserved.
 * 
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "BrokerQueryManager.h"


    
BrokerQueryManager::BrokerQueryManager(broker::endpoint* lhost,
        broker::message_queue* mq,std::string* btp)
{
    //point to broker topic object
    this->b_topic = btp;
    this->first_time = true;
    //point to local host object
    this->ptlocalhost = lhost;
    //pointer to message queue object
    this->ptmq = mq;
}

bool BrokerQueryManager::isQueryColumnInteger(const std::string& str)
{
    if(str.empty())
	{return false;}
    // Iterates over all elements of string to check whether all number?
    return std::all_of(str.begin(),str.end(), ::isdigit);
}

std::string BrokerQueryManager::getLocalHostIp()
{
    //Map::iterator to iterator over Osquery::Row columns
    typedef std::map<std::string, std::string>::const_reverse_iterator pt;
    
    //Using osquery; queries interface_addresses table
    QueryData ip_table = 
            getQueryResult("SELECT address FROM interface_addresses");
    // loop over each interface Row
    for(auto& r: ip_table)
    {
        for(pt iter = r.rbegin(); iter != r.rend(); iter++)
        {
            if((iter->second).size()>9 && (iter->second).size()<16)
            {
                return iter->second;
            }
        }
        std::cout<<std::endl;
    }
    return "";
}

input_query BrokerQueryManager::brokerMessageExtractor(
const broker::message& msg)
{
    input_query temp;
    std::string broQuery = broker::to_string(broker::message(msg));
    
    // will remove [] form start and end of string
    broQuery = broQuery.substr(1,broQuery.size()-2);
    int loc = broQuery.find(',');
    
    //returns the event part
    temp.event_name = broQuery.substr(0,loc);
    //returns the query  string
    temp.query = broQuery.substr(loc+2,broQuery.size());
    
    //will throw an exception if query is not a proper SQL string
    if(temp.query.substr(0,6)!= "SELECT")
    {  
        throw(std::string("Please send Proper formated query"));
    }
    else
        return temp;
}

bool BrokerQueryManager::getQueriesFromBrokerMessage(pollfd* pfd,
        bool &connected)
{
    int rv = poll(pfd,1,2000);
    if(!(rv== -1) && !(rv==0))
    {
        //loop for all messages in queue
        for(auto& msg: this->ptmq->need_pop())
        {
            //temporary variable for input queries
            input_query inString;
            try
            {
                inString = brokerMessageExtractor(msg);
            }
            catch(std::string e)
            {
            std::cout<<e <<std::endl;
            std::cout<<"Try Re-establishing Connection"<<std::endl;
            this->ptlocalhost->incoming_connection_status().need_pop().clear();
            // re-initialize all vectors
            BrokerQueryManager::ReInitializeVectors();
            //set connection flag to false
            connected = false;
            }
            in_query_vector.emplace_back(inString);
        }
        return true;
    }
    return false;
}


bool BrokerQueryManager::getEventsFromBrokerMessage()
{
    for(int i=0;i<in_query_vector.size();i++)
    {  
        std::string s= in_query_vector[i].event_name;
        int loc1= s.find(':',0);
        int loc2= s.find('_',loc1);
        s = s.substr(loc1+2,loc2-loc1-2);
        event.emplace_back(s);
    }
    return (!event.empty())? true: false;
}

bool BrokerQueryManager::queryColumnExtractor()
{
    //loop for all input queries
    for(int i=0;i<in_query_vector.size();i++)
    {
        input_query print = in_query_vector.at(i);
        std::cout<<print.query<<std::endl;
        // Extracts the columns in query using osquery::split function
        for(auto& c1: osquery::split(print.query,"SELECT"))
        {
            for(auto& c2: osquery::split(c1,"FROM"))
            {
                for(auto& c3: osquery::split(c2,","))
                {
                    qc.push_back(c3);
                }
                break;
            }
            break;
        }
        // stores the corresponding query columns 
        qmap.insert(query_columns_map::value_type(i,qc));
        qc.clear();
    }
    return (!qmap.empty()) ? true: false;
    
}

bool BrokerQueryManager::queryDataResultVectorInit()
{
    for(int i=0;i<in_query_vector.size();i++)
    { 
        query_update temp;
        temp.current_results = getQueryResult(in_query_vector[i].query);
        temp.old_results = temp.current_results;
        temp.current_results.clear();
        temp.current_results = getQueryResult(in_query_vector[i].query);
        out_query_vector.emplace_back(temp);
        this->first_time = false;
    }
    return (!out_query_vector.empty()) ? true: false;
}

bool BrokerQueryManager::ReInitializeVectors()
{
    first_time = true;
    if(!out_query_vector.empty())
    {
        out_query_vector.clear();
    }
    if(!event.empty())
    {
        event.clear();
    }
    if(!qc.empty())
    {
        qc.clear();
    }
    if(!qmap.empty())
    {
        qmap.clear();
    }
    if(!in_query_vector.empty())
    {
        in_query_vector.clear();
    }
  return (in_query_vector.empty()) ? true :false;  
}

void BrokerQueryManager::diffResultsAndEventTriger(int& i)
{
    //After each 1sec Daemon will query
    usleep(1000000); //After each 5sec Daemon will query
    out_query_vector[i].current_results =
            getQueryResult(in_query_vector[i].query);
    
    //osquery::diff function to calculate difference in two query results 
    // for corresponding query.
    diff_result = osquery::diff(out_query_vector[i].old_results,
            out_query_vector[i].current_results);

    // check if new rows added and master is also interested in added events
    if((diff_result.added.size() > 0) && (event[i]=="added"))
    {
        //if success then send update to master
        sendUpdateEventToMaster(diff_result.added,
                in_query_vector.at(i).event_name,i);
    }
    // check if any rows deleted and master is also interested in removed events
    if((diff_result.removed.size() > 0) && (event[i]=="removed"))
    {
        //if success then send update to master
        sendUpdateEventToMaster(diff_result.removed,
                in_query_vector.at(i).event_name,i);
    }
    out_query_vector.at(i).old_results = out_query_vector.at(i).current_results;
}


void BrokerQueryManager::sendUpdateEventToMaster(const QueryData& temp,
        std::string& table_name, int& iterator)
{
    typedef std::map<std::string, std::string>::const_reverse_iterator pt;
    broker::message msg;
    for (auto& r: temp)
    {
        if(!qmap.empty())
        {
            msg.emplace_back(table_name);
            msg.push_back(getLocalHostIp());
            //iterator for no of columns in corresponding query
            for(int i=0;i<qmap[iterator].size();i++)
            {
                // iterator for each row column
                for(pt iter = r.rbegin(); iter != r.rend(); iter++)
                {
                    if(iter->first == qmap[iterator][i])
                    {
                        //check if column value is integer
                        if(isQueryColumnInteger(iter->second))
                        {
                            msg.emplace_back(std::stoul(iter->second.c_str()));
                        }
                        else
                        {
                            msg.emplace_back(iter->second);
                        }
                        break;
                    }
                }
            }
        }
        //send broker message 
        std::cout<<msg<<std::endl;
        this->ptlocalhost->send(*b_topic, msg);
        usleep(500000);
        msg.clear();
    }
     this->ptmq->want_pop().clear();
}


void BrokerQueryManager::queriesUpdateTrackingHandler()
{
    
    for(int i=0;i<out_query_vector.size();i++)
    {
        BrokerQueryManager::diffResultsAndEventTriger(i);
    }
    
}

QueryData BrokerQueryManager::getQueryResult(const std::string& queryString)
{
    QueryData qd;
    osquery::queryExternal(queryString, qd);
    
    return qd;
}
