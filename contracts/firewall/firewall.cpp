#include "firewall.hpp"

namespace EosShield{
    
    void Firewall::addacct(account_name account, uint64_t riskLevel, string& url, string& details, string& cveReference){
        require_auth(_self);

        cveIndex cves(_self, _self);

        auto iterator = cves.find(account);
        eosio_assert(iterator == cves.end(), "That account is alread listed. Use update instead.");

        cves.emplace(_self, [&](auto& cve){
            cve.accountName = account;
            cve.riskLevel = riskLevel;
            cve.url = url;
            cve.details = details;
            cve.cveReference = cveReference;
        });
        print("CVE added");
    }

    void Firewall::updateacct(account_name account, uint64_t riskLevel, string& url, string& details, string& cveReference){
        require_auth(_self);

        cveIndex cves(_self, _self);

        auto iterator = cves.find(account);
        eosio_assert(iterator != cves.end(), "That account does not exist. Use create instead.");

        cves.modify(iterator, _self, [&](auto& cve){
            cve.riskLevel = riskLevel;
            cve.url = url;
            cve.details = details;
            cve.cveReference = cveReference;
        });
    }

    void Firewall::checkacct(account_name account, uint64_t riskLevel){
        cveIndex cves(_self, _self);

        auto iterator = cves.find(account);
        if(iterator == cves.end()){
            print("That account is not known to be malicious.");
        }
        else{
            auto cve = cves.get(account);
            if(cve.riskLevel < riskLevel){
                print("That account has an acceptable risk level of: ", cve.riskLevel);
            }
            else{
                string failure_message = "That account is known to be malicious. Transaction failing for reason: ";
                failure_message += cve.details;
                eosio_assert(false, failure_message.c_str());
            }
        }
    }

}
