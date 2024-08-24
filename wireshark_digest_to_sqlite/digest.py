"""Provide utility functions for working with deeply nested JSONs."""

import itertools


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


def strip_matching_prefix(to_strip, to_match_prefix):
    """Return to_strip with any shared prefix of to_match_prefix removed."""
    letter_pairs = zip(to_strip, to_match_prefix)
    iterate_to_no_match = itertools.takewhile(
        lambda pair: pair[0] == pair[1], letter_pairs
    )
    matching_prefix = "".join(pair[0] for pair in iterate_to_no_match)
    return to_strip.removeprefix(matching_prefix)


class JsonObject:
    """Provide alternative to dict in reading JSON objects.

    When reading or loading a JSON object, use this as an alternative to dicts
    to be able to access values through attributes instead of keys. Can be used
    with `object_hook` for json.load.

    Subclass this for "types" of objects (e.g. an array of JSON objects of
    similar structure) that may require additional processing, attributes, or
    methods.
    """

    def __init__(self, obj_dict):
        """Initialize with a dict of attribute, value pairs."""
        self.__dict__.update(obj_dict)
        self._json_raw = obj_dict

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

    def promote(self, subclass, val_for_prefix_strip=None):
        """Return a subclass instance formed from the original input to self.

        Return a subclass instance created by calling the subclass.__init__ on
        the argument this self was initialized with. In some use cases, the
        keys of the original data need to be renamed such that a common prefix
        of those keys is removed.
        """
        if val_for_prefix_strip:
            promoted = subclass(
                {
                    strip_matching_prefix(key, val_for_prefix_strip): value
                    for key, value in self._json_raw.items()
                }
            )
        else:
            promoted = subclass(self._json_raw)
        return promoted


def promote_named_objects(obj, object_map, keep_dots=False, strip_prefixes=False):
    """Convert JsonObjects to new classes by key names.

    For each label in obj that is in object_map, promote the value(s) at key
    from the generic JsonObject to the class identified by object_map. Then
    return JsonObject(obj). Can be used with `object_hook` when loading JSON.
    See testing of this function for an example that avoids lambda functions by
    using functools.partial to provide the object_map.

    Keys with '.'s are inconvenient because they cannot be accessed directly as
    attributes (see object.a.b vs getattr(object, "a.b")). When keep_dots is
    False, '.'s in keys are replaced with '_'s.

    A common use case with nested json objects carries the key name for an
    object into the keys of the object itself. To automatically remove this
    redundancy, use the strip_prefixes option.
    """
    # can't rename keys mid for-loop so need a destination for the changes
    dst_obj = dict()

    for key, preprocessed in obj.items():
        promo_cls = object_map.get(key, JsonObject)
        delimeter = "." if keep_dots else "_"
        new_key = key if keep_dots else key.replace(".", "_")
        strip_key = f"{new_key}{delimeter}" if strip_prefixes else None
        if isinstance(preprocessed, JsonObject):
            reprocessed = preprocessed.promote(promo_cls, strip_key)
        elif isinstance(preprocessed, list):
            reprocessed = [
                (
                    entry.promote(promo_cls, strip_key)
                    if isinstance(entry, JsonObject)
                    else entry
                )
                for entry in preprocessed
            ]
        else:
            reprocessed = preprocessed
        dst_obj[new_key] = reprocessed
    return JsonObject(dst_obj)
