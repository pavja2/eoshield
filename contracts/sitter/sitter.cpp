#include <eosiolib/eosio.hpp>
#include <eosiolib/print.hpp>
#include <string>

namespace Sitter{
    using namespace eosio;
    using std::string;

    class Sitter : public contract{
        using contract::contract;

        public:
            //@abi action
            void newpost(account_name account, string& content){
                require_auth(account);

                postIndex posts(_self, _self);

                posts.emplace(_self, [&](auto& post){
                    post.author = account;
                    post.content = content;
                    post.key = posts.available_primary_key();
                });
                print("Post Made");
            }
        
        private:
            //@abi table post i64
            struct post{
                uint64_t key;
                account_name author;
                string content;

                uint64_t primary_key() const{return key;}

                EOSLIB_SERIALIZE(post, (key)(author)(content))
            };

            typedef multi_index<N(post), post> postIndex;
    };

    EOSIO_ABI(Sitter, (newpost));
}