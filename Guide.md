###Client Guide###
* Clone, compile & build the https://github.com/sami2316/osquery repo. I have updated my local work to this repo.

* ```cp -rf /home/chenone2316/osquery/build/centos7/osquery/BrokerQueryPlugin.ext``` ```/usr/lib/osquery/extensions```
* Make the file ```/etc/osquery/extensions.load``` with following contents.

  ```
  /usr/lib/osquery/extensions/BrokerQueryPlugin.ext
  ```
  
* run ```osqueryd --extensions_autoload=/etc/osquery/extension.load


###Master Guide###
* Follow
    https://github.com/sami2316/random_osBro/tree/master/Master
