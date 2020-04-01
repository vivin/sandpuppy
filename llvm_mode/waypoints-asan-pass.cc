#include "fuzzfactory.hpp"

using namespace fuzzfactory;

class AsanFeedback : public DomainFeedback<AsanFeedback> {
public:
    AsanFeedback(Module& M) : DomainFeedback<AsanFeedback>(M, "__afl_asan_dsf") { }
};

FUZZFACTORY_REGISTER_DOMAIN(AsanFeedback);
