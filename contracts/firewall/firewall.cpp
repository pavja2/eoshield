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

    void Firewall::reportacct(account_name reporter, account_name account, string& url, string& details){
        require_auth(reporter);

        reportIndex reports(_self, _self);
        eosio_assert(reporter != account, "You can't report yourself silly!");

        reports.emplace(_self, [&](auto& report){
            report.key  = reports.available_primary_key();
            report.accountName = account;
            report.url = url;
            report.details = details;
        });

        cveIndex cves(_self, _self);
        auto iterator = cves.find(account);
        if(iterator == cves.end()){
            //set a minimal report for the account
            cves.emplace(_self, [&](auto& cve){
                cve.accountName = account;
                cve.riskLevel = uint64_t(1);
                cve.url = std::string("");
                cve.details = std::string("One or more users reported this account as malicious but the report has not been confirmed.");
                cve.cveReference = std::string("");
            });
        }
    }
}
