"""Provide utility functions for working with deeply nested JSONs."""

def nodes(json_data):
    """Return iterable of all leaf nodes (non-dict and non-array) in a JSON."""
    to_visit = None
    if isinstance(json_data, list):
        to_visit = json_data
    elif isinstance(json_data, dict):
        to_visit = json_data.values()

    if to_visit:
        for value in to_visit:
            yield from nodes(value)
    else:
        yield json_data


def labels(json_data):
    """Return iterable of the labels (dictionary keys) at any level in a JSON."""
    if isinstance(json_data, list):
        for value in json_data:
            yield from labels(value)
    elif isinstance(json_data, dict):
        for key, value in json_data.items():
            yield key
            yield from labels(value)
    else:
        pass


class JsonObject:
    """Provide alternative to dict in reading JSON objects.
    
    When reading or loading a JSON object, use this as an alternative to dicts
    to be able to access values through attributes instead of keys. Can be used
    with `object_hook` for json.load.

    Subclass this for "types" of objects (e.g. an array of JSON objects of
    similar structure) that may require additional processing, attributes, or
    methods. 
    """
    def __init__(self, /, **kwargs):
        """Provide each attribute as a keyword argument."""
        self.__dict__.update(kwargs)
        self._json_raw = kwargs

    
    @classmethod
    def from_dict(cls, dictionary):
        """Construct from a dict instead of keywords."""
        return cls(**dictionary)

    def __repr__(self):
        """Return a string with the defining key/value pairs."""
        item_descriptions = (
            f"{key}={value}"
            for key, value in self.__dict__.items()
            if key != "_json_raw"
        )
        joined_item_descriptions = f"{', '.join(item_descriptions)}"

        name_description = f"{type(self).__name__}"

        return f"{name_description}({joined_item_descriptions})"

    def __eq__(self, other):
        """Return if self has the same defining key/value pairs as other."""
        return self._json_raw == other._json_raw


def promote_named_objects(obj, object_map):
    """Convert JsonObjects to new classes by key names.

    For each label in obj that is in object_map, promote the value(s) at key
    from the generic JsonObject to the class identified by object_map. Then
    return JsonObject(obj). Can be used with `object_hook` when loading JSON.
    """
    for key, preprocessed in obj.items():
        promo_cls = object_map.get(key)
        if not promo_cls:
            pass
        elif isinstance(preprocessed, JsonObject):
            obj[key] = promo_cls(**preprocessed._json_raw)
        elif isinstance(preprocessed, list):
            obj[key] = [
                promo_cls(**entry._json_raw) if isinstance(entry, JsonObject) else entry
                for entry in preprocessed
            ]
        else:
            pass
    return JsonObject(**obj)
