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

    void Firewall::checktrust(account_name account){
        trustedIndex trusteds(_self, _self);
        auto iterator = trusteds.find(account);
        if(iterator == trusteds.end()){
            eosio_assert(false, "That account has not been vetted and approved.");
        }
    }

    void Firewall::reportacct(account_name reporter, account_name account, string& url, string& details){
        require_auth(reporter);

        reportIndex reports(_self, _self);
        eosio_assert(reporter != account, "You can't report yourself silly!");

        auto reportedIndex = reports.get_index<N(account)>();
        auto itr = reportedIndex.find(account);

        //If it doesn't exist we create a new one
        if(itr == reportedIndex.end()){
            reports.emplace(_self, [&](auto& report){
                report.key  = reports.available_primary_key();
                report.accountName = account;
                report.url = url;
                report.details = details;
            });
        }
        else{
            auto iterator = reports.find(itr->key);
            reports.modify(iterator, _self, [&](auto& report){
                report.details = details;
                report.url = url;
            });
        }

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

    void Firewall::addmalware(checksum256& codeHash, uint64_t riskLevel, string& details){
        require_auth(_self);

        malwareIndex signatures(_self, _self);
        auto hashIndex = signatures.get_index<N(codeHash)>();
        auto itr = hashIndex.find(malware::get_commitment(codeHash));
        //create if it doesn't exist
        if(itr == hashIndex.end()){
            signatures.emplace(_self, [&](auto& malware){
                malware.key = signatures.available_primary_key();
                malware.riskLevel = riskLevel;
                malware.details = details;
                malware.codeHash = codeHash;
            });
        }
        else{ //otherwise update the risk settings
            auto iterator = signatures.find(itr->key);
            signatures.modify(iterator, _self, [&](auto& malware){
                malware.riskLevel = riskLevel;
                malware.details = details;
            });
        }
    }

    void Firewall::addtrusted(account_name account, string& description, checksum256& codeHash){
        require_auth(_self);

        trustedIndex trusteds(_self, _self);
        auto iterator = trusteds.find(account);
        if(iterator == trusteds.end()){
            trusteds.emplace(_self, [&](auto& trusted){
                trusted.account = account;
                trusted.description = description;
                trusted.codeHash = codeHash;
            });
        }
        else{
            trusteds.modify(iterator, _self, [&](auto& trusted){
                trusted.description = description;
                trusted.codeHash = codeHash;
            });
        }
        print("Created Trusted Acco unt");
    }
}
