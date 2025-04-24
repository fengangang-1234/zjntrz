from ipaddress import ip_address
import time
import threading 

class MQTTControlPlane:

    def __init__(self):
        self.running = True 
        self.bfrt = bfrt  
        self.p4 = self.bfrt.mqtt.pipe 

        self.degista = self.p4.SwitchIngressDeparser.digesta
        self.degistb = self.p4.SwitchIngressDeparser.pipe.SwitchIngressDeparser.digestb
        self.degistc = self.p4.SwitchIngressDeparser.pipe.SwitchIngressDeparser.pipe.SwitchIngressDeparser.digestc
        self.degistd = self.p4.SwitchIngressDeparser.pipe.SwitchIngressDeparser.pipe.SwitchIngressDeparser.pipe.SwitchIngressDeparser.digestd

        self.forward_decision = self.p4.SwitchIngress.forward_decision_tb
        self.connect_token_conf = self.p4.SwitchIngress.connect_token_conf_tb
        self.blacklist = self.p4.SwitchIngress.mqtt_connect_blacklist_tb
        self.mqtt_acl = self.p4.SwitchIngress.mqtt_acl_tb

        self.session_info = {}
        self.index = 0

        self.conn_req_threshold=10

        self.base_forward_data = {149:150,150:149}


    # init base forward
    def update_forward_decision(self, key, value):
        try:
            self.forward_decision.add_with_forward(key,value)
        except:
            self.forward_decision.mod_with_forward(key,value)
    
    def init_forward_decision(self):
        for key, value in self.base_forward_data.items():
            self.update_forward_decision(key, value)
    
    # MQTT ACL tools
    def mqtt_acl_update(self, key1, key2, key3):
        try:    
            self.mqtt_acl.add_with_session_record(key1,key2,key3)
        except Exception as e:
            self.mqtt_acl.mod_with_session_record(key1,key2,key3)
    
    def mqtt_acl_delete(self, key1, key2, key3):
        try:    
            self.mqtt_acl.delete(key1,key2,key3)
            print("delete",key1,key2,key3)
        except Exception as e:
            return
        
    # token config tools
    def update_connect_token_conf(self,value):
        try:
            self.connect_token_conf.add_with_set_token_conf(1,value)
        except Exception as e:
            self.connect_token_conf.mod_with_set_token_conf(1,value)    
        

    def update_blacklist_table(self,key1):
        try:
            self.blacklist.add_with_is_in_blacklist(key1)
        except Exception as e:
            return
    
    def delete_blacklist_table(self,key1):
        try:
            self.blacklist.delete(key1)
        except Exception as e:
            return
    
    def set_tocken_conf(self):
        try:    
            self.connect_token_conf.add_with_set_token_conf(1,100,100)
        except Exception as e:
            self.connect_token_conf.mod_with_set_token_conf(1,100,100)
        
    def delete_tocken_conf(self):
        try:
            self.connect_token_conf.delete(1)
        except Exception as e:
            return

        
    # data process
    def session_analysis(self):
        for key, value in self.session_info.items():
            src = key
            timetmp = time.time()
            a = value["conn_req_count"]
            self.session_info[key]["conn_req_count"][(self.index-2)%20] = 0
            if  self.session_info[key]["is_inblacklist"][0]==1:
                if timetmp - self.session_info[key]["is_inblacklist"][1] > 2:
                    self.delete_blacklist_table(src)
                    self.session_info[key]["is_inblacklist"]=[0,0]
            else:
                conn_req_num = a[self.index]+a[(self.index-1)%20]+a[(self.index-2)%20]
                if conn_req_num > self.conn_req_threshold:
                    print("DoS Warning, Entry ",key," into Blacklist")
                    self.update_blacklist_table(src)
                    self.session_info[key]["is_inblacklist"]=[1,timetmp]
        return 0


            

    def convert_int_to_ip(self, ip_int):
        first_octet = (ip_int >> 24) & 0xFF 
        second_octet = (ip_int >> 16) & 0xFF
        third_octet = (ip_int >> 8) & 0xFF
        fourth_octet = ip_int & 0xFF
        return f"{first_octet}.{second_octet}.{third_octet}.{fourth_octet}"
    
    def digesta_callback(self, dev_id, pipe_id, direction, parser_id, session, data):
        for data_term in data:
            src_addr = self.convert_int_to_ip(data_term["src_addr"])
            key = src_addr
            if key in self.session_info:
                self.session_info[key]["ttl"] = data_term["ttl"]
                self.session_info[key]["conn_req_count"][self.index] += 1
                if data_term["src_addr"] in self.session_info[key]["senssion_state"]:
                    self.session_info[key]["senssion_state"][data_term["src_port"]][1] = time.time()
                else:
                    new_session_info=[0,time.time()]
                    self.session_info[key]["senssion_state"][data_term["src_port"]] = new_session_info
            else:
                print("\nNew MQTT Session Request with  {}:{}".format(src_addr,data_term["src_port"]))
                value = {
                    "senssion_state":{data_term["src_port"]:[0,time.time()]},
                    "ttl": data_term["ttl"],
                    "conn_req_count": [0 for i in range(20)],
                    "is_inblacklist": [0,0]
                }
                value["conn_req_count"][self.index] += 1
                self.session_info[key] = value
        
        return 0

    def digestb_callback(self, dev_id, pipe_id, direction, parser_id, session, data):
        for data_term in data:
            dst_addr = self.convert_int_to_ip(data_term["dst_addr"])
            # print("New MQTT Session Connect with  {}:{}".format(dst_addr,data_term["dst_port"]))
            key = dst_addr
            if key in self.session_info:
                self.mqtt_acl_update(dst_addr,data_term["dst_port"],self.session_info[key]["ttl"]) 
                if data_term["dst_addr"] in self.session_info[key]["senssion_state"]:
                    self.session_info[key]["senssion_state"][data_term["dst_port"]][0] = 1
                    self.session_info[key]["senssion_state"][data_term["dst_port"]][1] = time.time()
                else:
                    new_session_info=[1, time.time()]
                    self.session_info[key]["senssion_state"][data_term["dst_port"]] = new_session_info
                
        return 0
    
    def digestc_callback(self, dev_id, pipe_id, direction, parser_id, session, data):
        for data_term in data:
            if (data_term["src_port"] == 1883):
                continue
            else:
                src_addr = self.convert_int_to_ip(data_term["src_addr"])
                key = src_addr
                if key in self.session_info:
                    self.session_info[key]["ttl"] = data_term["ttl"] 
                    self.session_info[key]["senssion_state"][data_term["src_port"]][1] = time.time()       
        return 0
    
    def digestd_callback(self, dev_id, pipe_id, direction, parser_id, session, data):
        for data_term in data:
            if (data_term["src_port"] == 1883):
                continue
            else:
                src_addr = self.convert_int_to_ip(data_term["src_addr"])
                key = src_addr
                # print("New MQTT Session DisConnect with  {}:{}".format(src_addr,data_term["src_port"]))
                if key in self.session_info:
                    if data_term["src_port"] in self.session_info[key]["senssion_state"]:
                        self.session_info[key]["senssion_state"][data_term["src_port"]][0] = 0
                        ttl = self.session_info[key]["ttl"]   
                        self.mqtt_acl_delete(src_addr,data_term["src_port"],ttl)  
                            
        return 0
    
    def clean_degist_callback(self):
        try:
            self.degista.callback_deregister()
        except:
            print("Clean Failded in degista")
        
        try:
            self.degistb.callback_deregister()
        except:
            print("Clean Failded in degistb")

        try:
            self.degistc.callback_deregister()
        except:
            print("Clean Failded in degistc")

        try:
            self.degistd.callback_deregister()
        except:
            print("Clean Failded in degistd")
    
    def handle_digesta(self):
        try:
            self.degista.callback_register(self.digesta_callback)
        except:
            self.degista.callback_deregister()
            self.degista.callback_register(self.digesta_callback)
    
    def handle_digestb(self):
        try:
            self.degistb.callback_register(self.digestb_callback)
        except:
            self.degistb.callback_deregister()
            self.degistb.callback_register(self.digestb_callback)
    
    def handle_digestc(self):
        try:
            self.degistc.callback_register(self.digestc_callback)
        except:
            self.degistc.callback_deregister()
            self.degistc.callback_register(self.digestc_callback)

    def handle_digestd(self):
        try:
            self.degistd.callback_register(self.digestd_callback)
        except:
            self.degistd.callback_deregister()
            self.degistd.callback_register(self.digestd_callback)
    
    def init_all(self):
        self.init_forward_decision()

        self.handle_digesta()
        self.handle_digestb()
        self.handle_digestc()
        self.handle_digestd()

    def app_run(self):
        self.init_all()

        # def run_session_analysis(): 
        #     while self.running:
        #         self.session_analysis()
        #         self.index = (self.index + 1) % 20
        #         time.sleep(1)

        # session_thread = threading.Thread(target=run_session_analysis)  
        # session_thread.start() 
        try:
            while True:
                self.index = (self.index + 1) % 20

                command = input("MQTTControlPlane>>>")
                if command == "log":
                    with open("session_info.log", "w") as log_file:
                        log_file.write("{")
                        for key, value in self.session_info.items():
                            log_file.write(f"{key}: {value}")
                        log_file.write("}")
                    print("keep log successful")
                elif command == "dump":
                    for key, value in self.session_info.items():
                        print(f"{key}: {value}\n")

                elif command == "exit" or command == "quit":
                    self.clean_degist_callback()
                    self.running = False
                    # session_thread.join()
                    break
                elif command == "set_tocken":
                    self.set_tocken_conf()
                    continue
                elif command == "del_tocken":
                    self.delete_tocken_conf()
                    continue
                
                elif command == "":
                    continue

                else:
                    print("Wrong command, try others")


        except KeyboardInterrupt:
            print("Over")
    



# 示例使用
if __name__ == "__main__":  
    mqtt_control_plane = MQTTControlPlane()
    mqtt_control_plane.app_run()


    