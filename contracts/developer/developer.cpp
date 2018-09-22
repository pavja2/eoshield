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
            void test(){
                transaction trx;
                action(
                    permission_level{_self, N(active)},
                    N(hashtest), N(forward),
                    std::make_tuple(trx)
                ).send();
            }
    };

    EOSIO_ABI(Developer, (test))
}