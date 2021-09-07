import sys
def generate_rules(length):
    for i in range(1,length+1):
        fw = open("rules/s"+str(i-1)+"-commands.txt","w")
        fw.write("table_clear tbl_determine_task\n")
        fw.write("table_clear tbl_do_telemetry_level_0\n")
        fw.write("table_clear tbl_forward\n")
        fw.write("table_clear tbl_ttl_rules\n")
        fw.write("\n")
        for j in range(1,4):
            fw.write("table_add tbl_do_telemetry_level_0 write_task_"+str(i)+"_value "+str(j)+' => '+str(j)+'\n')
        fw.write("\n")
        for j in range(1,length+1):
            smaller = False
            if j ==i:
                fw.write("table_add tbl_forward forward 10.0.0."+(str)(j-1)+" => 1\n")
            elif j < i  :
                smaller = True
                fw.write("table_add tbl_forward forward 10.0.0."+(str)(j-1)+" => 2\n")
            else:
                if smaller:
                    fw.write("table_add tbl_forward forward 10.0.0."+(str)(j-1)+" => 3\n")
                else:
                    fw.write("table_add tbl_forward forward 10.0.0."+(str)(j-1)+" => 2\n")
        fw.write("\n")
        global_hash_range = 100000
        for hop in range(1, 10):
                fw.write("table_add tbl_ttl_rules get_approximation " + str(hop) + " => " + str(int(global_hash_range // hop)) + "\n")
        fw.write("\n")
        if i == 1 :
            fw.write("table_add tbl_determine_task write_task_3 0->33 => 0\n")
            fw.write("table_add tbl_determine_task write_task_2 34->66 => 0\n")
            fw.write("table_add tbl_determine_task write_task_1 67->99 => 0\n")

if __name__ == '__main__':
    length = int(sys.argv[1])
    generate_rules(length)