#include <iostream>
#include <fstream>
#include <unistd.h>
#include <pcap/pcap.h>
#include <dirent.h>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <mutex>
#include <tclap/CmdLine.h>
#include <atomic>

bool show_interfaces = false;
bool show_traffic = false;
int count_traffic = 0;


std::string getFirstLineFile(const std::string &path) {
    std::string line;
    std::ifstream inFile(path);
    if (!inFile.is_open()) {
        std::cerr << "unable to open file " + path << '\n';
        return "";
    }
    getline(inFile, line);
    inFile.close();
    return line;
}

std::vector<std::string> getInterfaces() {
    std::vector<std::string> interfaces;
    std::string interface_directory = "/sys/class/net/";

    DIR *dir;
    if ((dir = opendir(interface_directory.c_str())) == NULL) {
        std::cerr << "could not open directory " + interface_directory << '\n';
        return interfaces;
    }

    struct dirent *interface;
    while ((interface = readdir(dir)) != NULL) {
        if (interface->d_type == 10 &&
            getFirstLineFile(interface_directory + interface->d_name + "/type") == "1" &&
            getFirstLineFile(interface_directory + interface->d_name + "/carrier") == "1") {
            std::string buf;
            buf.resize(128);
            readlink((interface_directory + interface->d_name).c_str(), &buf[0], 128);
            interfaces.emplace_back(interface->d_name);
            if (buf.find("virtual") == std::string::npos) {
            }
        }
    }
    closedir(dir);
    return interfaces;
}

void pcapHandler(u_char *args, const struct pcap_pkthdr *packet, const u_char *packet_body) {
    void **arguments = reinterpret_cast<void **>(args);

    auto *interface = reinterpret_cast<std::string *>(arguments[0]);
    auto *vlan_list = reinterpret_cast<std::map<std::string, std::set<unsigned short int>> *>(arguments[1]);
    auto *vlan_list_mutex = reinterpret_cast<std::mutex *>(arguments[2]);

    uint16_t vlan_id = packet_body[15];
    vlan_id |= ((((uint16_t) packet_body[14]) & 15u) << 8u);

    (*vlan_list_mutex).lock();
    (*vlan_list)[*interface].insert(vlan_id);
    (*vlan_list_mutex).unlock();

    if (show_traffic) {
        std::cout << count_traffic++ << ' ' << interface << ": " << vlan_id << '\n';
    }
}

void
lookInterface(std::string interface, std::map<std::string, std::set<unsigned short int>> &vlan_list,
              std::mutex &vlan_list_mutex) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program fp{};
    char filter_exp[] = "inbound && vlan";

    pcap_t *handle = pcap_open_live(interface.c_str(), BUFSIZ, 0, 1, error_buffer);
    if (handle == NULL) {
        std::cerr << "Failed to open device " << interface.c_str() << ": " << error_buffer << '\n';
        return;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Failed to parse filter " << filter_exp << ": " << pcap_geterr(handle) << '\n';
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Failed to install filter " << filter_exp << ": " << pcap_geterr(handle) << '\n';
        return;
    }

    void *arguments[3] = {&interface, &vlan_list, &vlan_list_mutex};

    if (show_interfaces) {
        std::cout << "looking " << interface << "...\n";
    }

    pcap_loop(handle, 0, pcapHandler, reinterpret_cast<u_char *>(arguments));

    pcap_freecode(&fp);
    pcap_close(handle);
}

std::map<std::string, std::set<unsigned short int>> getVlanList(int viewing_time) {
    std::map<std::string, std::set<unsigned short int>> vlan_list;
    std::mutex vlan_list_mutex;
    std::vector<std::string> interfaces = getInterfaces();

    int size = interfaces.size();
    std::thread thread_array[size];

    for (int i = 0; i < size; ++i) {
        thread_array[i] = std::thread(lookInterface, std::ref(interfaces[i]), std::ref(vlan_list),
                                      std::ref(vlan_list_mutex));
        thread_array[i].detach();
    }

    sleep(viewing_time);

    return vlan_list;
}

void printVlans(const std::map<std::string, std::set<unsigned short int>> &vlan_list) {
    std::cout << "\nFound VLANs:\n";
    for (auto interface = vlan_list.begin(); interface != vlan_list.end(); ++interface) {
        std::cout << interface->first << ": ";
        for (auto vlan = interface->second.begin(); vlan != interface->second.end(); ++vlan) {
            std::cout << *vlan << ' ';
        }
        std::cout << '\n';
    }
}


int main(int argc, char *argv[]) {
    int viewing_time;

    try {
        TCLAP::CmdLine cmd("sniffvlan", ' ', " v0.1");
        TCLAP::SwitchArg show_interfaces_arg("i", "show_interfaces", "Show the interfaces that are being viewed", cmd,
                                             false);
        TCLAP::SwitchArg show_traffic_arg("o", "show_traffic", "Show traffic online", cmd, false);
        TCLAP::ValueArg<int> viewing_time_arg("t", "viewing_time", "Interface sniffing time (default 2 sec)",
                                              false, 2, "seconds");
        cmd.add(viewing_time_arg);
        cmd.parse(argc, argv);

        show_traffic = show_traffic_arg.getValue();
        show_interfaces = show_interfaces_arg.getValue();

        viewing_time = viewing_time_arg.getValue();

    } catch (TCLAP::ArgException &e) {
        std::cerr << "error: " << e.error() << "for arg " << e.argId() << std::endl;
    }

    printVlans(getVlanList(viewing_time));
}


























