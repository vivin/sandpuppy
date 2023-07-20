import collections
import logging

l = logging.getLogger(name=__name__)


class WindowDict(collections.MutableMapping):

    def __init__(self, store=dict(), len_limit=0, recent_added=list()):
        self.store = store

        self.len_limit = len_limit
        self.recent_added = recent_added

        self.access_count = collections.defaultdict(int)

    def __contains__(self, key):
        return self.__keytransform__(key) in self.store

    def __getitem__(self, key):
        return self.store[self.__keytransform__(key)]

    def __setitem__(self, key, value):
        key = self.__keytransform__(key)
        if self.len_limit == 0:
            self.store[key] = value
        else:
            if key in self.store:
                self.recent_added.remove(key)
                self.recent_added.append(key)
            else:
                self.recent_added.append(key)
                self.store[key] = value
                if len(self.recent_added) > self.len_limit:
                    self.store.pop(self.recent_added.pop(0))

    def __delitem__(self, key):
        del self.store[self.__keytransform__(key)]

    def __iter__(self):
        return iter(self.recent_added)

    def __len__(self):
        return len(self.store)

    def __keytransform__(self, key):
        return key

    def copy(self):
        return WindowDict(
            self.store.copy(),
            self.len_limit,
            self.recent_added.copy(),
        )
