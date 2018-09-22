#include <eosiolib/eosio.hpp>
#include <eosiolib/print.hpp>
#include <eosiolib/transaction.hpp>
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
            void updateacct(account_name account, uint64_t riskLevel, string& url, string& details, string& cveReference);

            //@abi action
            void checkacct(account_name account, uint64_t riskLevel);

            //@abi action
            void reportacct(account_name reporter, account_name account, string& url, string& details);
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

            typedef multi_index<N(cve), cve> cveIndex;
            typedef multi_index<N(report), report,
                indexed_by<N(account), const_mem_fun<report, uint64_t, &report::get_account>>> reportIndex;
    };
    EOSIO_ABI(Firewall, (addacct)(updateacct)(checkacct)(reportacct))
}

