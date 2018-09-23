#include <eosiolib/eosio.hpp>
#include <eosiolib/print.hpp>
#include <eosiolib/transaction.hpp>
#include <string>

namespace Developer{
    using namespace eosio;
    using std::string;

    class Developer : public contract{
        using contract::contract;

        public:
            //@abi action
            void test(account_name account){
                print("authed");
                action(permission_level{_self, N(active)}, N(firewall), N(checkacct),std::make_tuple(account,uint64_t(0))).send();
            }
    };

    EOSIO_ABI(Developer, (test))
}