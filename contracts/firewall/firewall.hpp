#include <eosiolib/eosio.hpp>
#include <eosiolib/print.hpp>
#include <eosiolib/transaction.hpp>
#include <eosiolib/multi_index.hpp>
#include <eosiolib/dispatcher.hpp>
#include <string>

namespace EosShield {
    using namespace eosio;
    using std::string;

    class Firewall : public contract{
        using contract::contract;
        public:
            //@abi action
            void addacct(account_name account, uint64_t riskLevel, string& url, string& details, string& cveReference);

            //@abi action
            void addmalware(checksum256& codeHash, uint64_t riskLevel, string& details);

            //@abi action
            void updateacct(account_name account, uint64_t riskLevel, string& url, string& details, string& cveReference);

            //@abi action
            void checkacct(account_name account, uint64_t riskLevel);

            //@abi action
            void reportacct(account_name reporter, account_name account, string& url, string& details);

            //@abi action
            void addtrusted(account_name account, string& description, checksum256& codeHash);

            //@abi action
            void checktrust(account_name account);
        private:

            //@abi table cve i64
            struct cve {
                account_name accountName;
                uint64_t riskLevel;
                string url;
                string details;
                string cveReference;
                uint64_t primary_key() const {return accountName;}

                EOSLIB_SERIALIZE(cve, (accountName)(riskLevel)(url)(details)(cveReference))
            };

            //@abi table trusted i64
            struct trusted{
                account_name account;
                string description;
                checksum256 codeHash;

                uint64_t primary_key() const{return account;}
                EOSLIB_SERIALIZE(trusted, (account)(description)(codeHash))
            };
            
            //@abi table cve i64
            struct report {
                uint64_t key;
                account_name accountName;
                bool approved;
                string url;
                string details;

                uint64_t primary_key() const{ return key;}
                uint64_t get_account() const{return accountName;}
                
                EOSLIB_SERIALIZE(report, (key)(accountName)(approved)(url)(details))
            };

            //@abi table malware i64
            struct malware {
                uint64_t key;
                checksum256 codeHash;
                uint64_t riskLevel;
                string details;

                uint64_t primary_key() const{return key;}
                key256 get_hash()const {return get_commitment(codeHash); }

                static key256 get_commitment(const checksum256& commitment) {
                    const uint64_t *p64 = reinterpret_cast<const uint64_t *>(&commitment);
                    return key256::make_from_word_sequence<uint64_t>(p64[0], p64[1], p64[2], p64[3]);
                }

                EOSLIB_SERIALIZE(malware, (key)(codeHash)(riskLevel)(details))
            };

            typedef multi_index<N(cve), cve> cveIndex;
            typedef multi_index<N(report), report,
                indexed_by<N(account), const_mem_fun<report, uint64_t, &report::get_account>>> reportIndex;
            
            typedef multi_index<N(malware), malware,
                indexed_by<N(codeHash), const_mem_fun<malware, key256, &malware::get_hash>>> malwareIndex;
            
            typedef multi_index<N(trusted), trusted> trustedIndex;
    };
    EOSIO_ABI(Firewall, (addacct)(updateacct)(checkacct)(reportacct)(addmalware)(addtrusted)(checktrust))
}

