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
//#include <pthread.h>




using namespace osquery;

broker::endpoint PC("VM");

/*
 * 
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
        std::cout<<"In the Message Query Function\n";
        broker::message_queue mq("Testing", PC);
        pollfd pfd{mq.fd(), POLLIN, 0};      
        int rv;
        std::string temp_query;
        std::string out1;
        std::string out2;
        std::string out;
        auto status = Status(0,"OK");
        QueryData test;
        
        while(true)
        {
            rv = poll(&pfd,1,10000);
            if(!(rv== -1) && !(rv==0))
            {
                for(auto& msg : mq.need_pop())
                {
                    temp_query = brokerMessageExtractor(msg);
                    if(!temp_query.empty())
                    {
                        std::cout<<"Query = "<<temp_query<<std::endl;
                        test = brokerQuery(temp_query);
                        for (auto& r : test)
                        {
                            for(pt iter = r.begin(); iter != r.end(); iter++)
                            {
                               // std::cout << iter->first << ": "; 
                                out1 += iter->first + " | ";
                               // std::cout << iter->second <<std::endl ;
                                out2 += iter->second + " | " ;
                            }
                            out1 += "\n"; out2 +="\n";
                            out = out1 + out2 ;
                            std::cout << out ;
                            usleep(500000);
                            PC.send("Testing", broker::message{out});
                            usleep(500000);
                            out1=out2=out="\0";
                            break;
                        }
                    }
                  
                }
            }
        }
    }
    
    
    ///////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////
   
    QueryData brokerQuery(const std::string& queryString)
    {
        QueryData qd;
        osquery::queryExternal(queryString, qd);
        
                
        return qd;
    }
    
    //////////////////////////////////////////////////////////////////////////
    //*************************************************************************
        Status genConfig(std::map<std::string,std::string>& config)
        {
            return Status(0,"OK");
        }
    //////////////////////////////////////////////////////////////////////
      /* Status broker_osquery_init()
        {
            std::cout<<"In the broker_init() function"<<std::endl;
            //BrokerQueryPlugin b;
            auto status = Status(0,"OK");
            status = brokerConnection();
            if(status.ok())
            {
                brokerMessageQuery();
            }
            else
            {
                std::cout<<"Could not Connect";
            }
            return Status(0,"OK");
        }*/
    
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


