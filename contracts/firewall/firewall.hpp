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

            typedef multi_index<N(cve), cve> cveIndex;
    };
    EOSIO_ABI(Firewall, (addacct)(updateacct)(checkacct))
}