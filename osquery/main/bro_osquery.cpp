/* 
 * File:   main.cpp
 * Author: chenone2316
 *
 * Created on June 1, 2015, 1:46 PM
 */


#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <osquery/sdk.h>
#include <poll.h>
#include <iostream>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <osquery/filesystem.h>
#include <osquery/events.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/sql.h>
#include <pthread.h>




using namespace osquery;
/*
 * Global Variables
 */
const int size=5;
broker::endpoint PC("VM");
pthread_t query_thread[size];
int rc[size];

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

QueryData brokerQuery(const std::string& queryString)
{
    QueryData qd;
    osquery::queryExternal(queryString, qd);


    return qd;
}
    
/*
 * Thread Functions for Managing updated results
 */
void print_query_result(const QueryData& temp)
{
    typedef std::map<std::string, std::string>::const_iterator pt;
    std::string out1,out2,out;
    for (auto& r : temp)
    {
        for(pt iter = r.begin(); iter != r.end(); iter++)
        {
            out1 += iter->first + " | ";
            out2 += iter->second + " | " ;
        }
        out1 += "\n"; out2 +="\n";
        out = out1 + out2 ;
        std::cout << out ;
        usleep(500000);
        PC.send("Testing", broker::message{out});
        usleep(500000);
        out1=out2=out="\0";
    }
}
void *queryManager(void *in_query)
{   
    DiffResults diff_result; 
    
    QueryData result_1,result_2;
    std::string* query = reinterpret_cast<std::string*>(in_query);
    std::cout<<"Query = "<<*query<<std::endl;
    result_1 = brokerQuery(*query);
    print_query_result(result_1);
    while(true)
    {
        usleep(5000000); //After each 5sec Daemon will query 
        result_2 = brokerQuery(*query);
        diff_result = osquery::diff(result_1,result_2);
        if(diff_result.added.size() > 0)
        {
            usleep(500000);
            PC.send("Testing", broker::message{"New Added data"});
            usleep(500000);
            print_query_result(diff_result.added);
        }
        if(diff_result.removed.size() > 0)
        {
            usleep(500000);
            PC.send("Testing", broker::message{"Data Removed"});
            usleep(500000);
            print_query_result(diff_result.removed);
        }
        result_1 = result_2;
    }
    pthread_exit(NULL);
}
/*
 End of Functions
 */
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/*
 Osquery External Plugin Class 
 */
class BrokerQueryPlugin: public ConfigPlugin
{
private:
    typedef std::map<std::string, std::string>::const_iterator pt;
    QueryData bQresult;
public:
    ////////////////////////////////////////////////////////////////////////////
    //////////////////broker connection/////////////////////////////////////////
    Status brokerConnection()
    {
        std::cout<<"In the broker Connection\n";
        auto status = Status(0,"OK");
        broker::init();
        PC.peer("192.168.1.187",9999);
        auto conn_status = PC.outgoing_connection_status().need_pop();
        for(auto cs: conn_status)
        {
            if(cs.status == broker::outgoing_connection_status::tag::established)
            {
                std::cout<<"Connection Established"<<std::endl;
                break;
            }
            else
            {
                std::cout<<"Error: Connection Failed"<<std::endl;
                status = Status(-1,"Not Connected");
            }
        }
        return status;
    }
    ////////////////////////////////////////////////////////////////////////////
    
   
    ///////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////
    std::string brokerMessageExtractor(const broker::message &msg)
    {
        std::string broQuery = broker::to_string(broker::message(msg));
        broQuery = broQuery.substr(1,broQuery.size()-2);
        if(broQuery.substr(0,6)!= "SELECT")
        {  
            return "";
        }
        else
            return broQuery;
    }
    
    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    Status brokerMessageQuery()
    {
        int thread_count = 0;
        std::cout<<"In the Message Query Function\n";
        broker::message_queue mq("Testing", PC);
        pollfd pfd{mq.fd(), POLLIN, 0};      
        int rv;
        std::string inString;
        std::string *temp_query;
        auto status = Status(0,"OK");
        
        while(true)
        {
            rv = poll(&pfd,1,10000);
            if(!(rv== -1) && !(rv==0))
            {
                for(auto& msg : mq.need_pop())
                {
                    inString = brokerMessageExtractor(msg);
                    if(!inString.empty() && thread_count < 5)
                    {
                        temp_query = new std::string(inString);
                        rc[thread_count] = pthread_create(&query_thread[thread_count],NULL,queryManager,(void*)temp_query);
                        if(rc[thread_count])
                        {
                            exit(-1);
                        }
                        thread_count++;
                    }
                }
                  
            }
        }
    }
    
    //////////////////////////////////////////////////////////////////////////
    //*************************************************************************
        Status genConfig(std::map<std::string,std::string>& config)
        {
            return Status(0,"OK");
        }
    //////////////////////////////////////////////////////////////////////
    
};
void *broker_osquery_init(void *threadid)
{
    std::cout<<"In the broker_init() function"<<std::endl;
    BrokerQueryPlugin b;
    auto status = Status(0,"OK");
    status = b.brokerConnection();
    while(!status.ok())
    {
        b.brokerConnection();
    }
    b.brokerMessageQuery();
    pthread_exit(NULL);
}

//////////////////////////////////////////////////

// Note 3: Use REGISTER_EXTERNAL to define your plugin
REGISTER_EXTERNAL(BrokerQueryPlugin, "config", "brokerQuery")

int main(int argc, char* argv[]) {
    
    pthread_t broker_thread;
    int rc; long t=0;
    std::cout<<"Starting the program"<<std::endl;
    BrokerQueryPlugin b;
    //b.broker_osquery_init();
    rc = pthread_create(&broker_thread, NULL, broker_osquery_init, (void*)t);
    if(rc)
    {
        std::cout<< "Error in pthread_create(): " <<rc <<std::endl;
        exit(-1);                                       
    }
   
    
  // Note 4: Start logging, threads, etc.
  osquery::Initializer runner(argc, argv, OSQUERY_EXTENSION);
  std::cout<<"Initialized OSquery"<<std::endl;
  
  // Note 5: Connect to osqueryi or osqueryd.
  auto status = startExtension("brokerQuery", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
  }
  
  /*BrokerQueryPlugin b;
  b.genConfig();*/
    
  std::cout<<"Shutting downn extension"<<std::endl;
  // Finally shutdown.
  runner.shutdown();
  return 0;
}


