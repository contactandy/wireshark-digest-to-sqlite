"""Test routines from the digest module."""

import json
from collections.abc import Iterable

import pytest

from wireshark_digest_to_sqlite import digest


@pytest.fixture
def sample_json():
    return json.loads(
        """
        {
          "string": "Hello, world!",
          "number": 42,
          "boolean": true,
          "null": null,
          "array": [
            1,
            "two",
            false,
            null,
            [3, 4, 5],
            {"nestedKey": "nestedValue"}
          ],
          "object": {
            "key1": "value1",
            "key2": 2,
            "nestedArray": [6, 7, 8],
            "nestedObject": {
              "innerKey1": "innerValue1",
              "innerKey2": 9
            }
          }
        }
        """
    )


@pytest.mark.parametrize(
    "json_primitive,expected_nodes",
    [
        ("Hello, world!", ["Hello, world!"]),
        (42, [42]),
        (True, [True]),
        (None, [None]),
        ([3, 4, 5], [3, 4, 5]),
        ({"key1": "value1", "key2": "value2"}, ["value1", "value2"]),
    ],
)
def test_nodes_with_json_primitives(json_primitive, expected_nodes):
    """Test the nodes routine with JSON primitives."""
    assert list(digest.nodes(json_primitive)) == expected_nodes


def test_nodes(sample_json):
    """Test the nodes routine with combinations of JSON primitives."""
    sample_array = sample_json["array"]
    expected_nodes = [1, "two", False, None, 3, 4, 5, "nestedValue"]
    assert list(digest.nodes(sample_array)) == expected_nodes

    sample_dict = sample_json["object"]
    assert list(digest.nodes(sample_dict)) == ["value1", 2, 6, 7, 8, "innerValue1", 9]

    nodes_from_top = ["Hello, world!", 42, True, None]
    nodes_from_array = list(digest.nodes(sample_array))
    nodes_from_dict = list(digest.nodes(sample_dict))
    expected_nodes = nodes_from_top + nodes_from_array + nodes_from_dict
    assert list(digest.nodes(sample_json)) == expected_nodes

    assert isinstance(digest.nodes(sample_json), Iterable)


@pytest.mark.parametrize(
    "json_primitive,expected_labels",
    [
        ("Hello, world!", list()),
        (42, list()),
        (True, list()),
        (None, list()),
        ([3, 4, 5], list()),
        ({"key1": "value1", "key2": "value2"}, ["key1", "key2"]),
    ],
)
def test_labels_with_json_primitives(json_primitive, expected_labels):
    """Test the labels routine with JSON primitives."""
    assert list(digest.labels(json_primitive)) == expected_labels


def test_labels(sample_json):
    """Test the labels routine with combinations of JSON primitives."""
    sample_array = sample_json["array"]
    assert list(digest.labels(sample_array)) == ["nestedKey"]

    sample_dict = sample_json["object"]
    top_level_lables = list(sample_dict.keys())
    lower_level_labels = list(sample_dict["nestedObject"].keys())
    assert list(digest.labels(sample_dict)) == top_level_lables + lower_level_labels

    labels_from_top = list(sample_json.keys())
    labels_from_array = list(digest.labels(sample_array))
    labels_from_dict = list(digest.labels(sample_dict))
    expected_labels = labels_from_top + labels_from_array + labels_from_dict
    assert sorted(list(digest.labels(sample_json))) == sorted(expected_labels)

    assert isinstance(digest.labels(sample_json), Iterable)


def test_JsonObject(sample_json):
    """Test the JsonObject class."""
    sample_obj = digest.JsonObject(key1="value1", key2="value2")
    assert sample_obj.key1 == "value1"
    assert sample_obj.key2 == "value2"

    sample_obj_same = digest.JsonObject(key2="value2", key1="value1")
    assert sample_obj == sample_obj_same
    sample_obj_diff = digest.JsonObject(key1="value2", key2="value2")
    assert sample_obj != sample_obj_diff
    sample_obj_diff = digest.JsonObject(key1="value1")
    assert sample_obj != sample_obj_diff
    sample_obj = digest.JsonObject(key3="value1", key2="value2")
    assert sample_obj != sample_obj_diff


    sample_dict = sample_json["object"]
    json_obj = digest.JsonObject(**sample_dict)
    for key, value in sample_dict.items():
        assert getattr(json_obj, key) == value

    from_dict_obj = digest.JsonObject.from_dict(sample_dict)
    assert from_dict_obj == json_obj

    sample_raw = json.dumps(sample_json)
    sample_json_obj = json.loads(
        sample_raw, object_hook=lambda x: digest.JsonObject(**x)
    )
    assert isinstance(sample_json_obj, digest.JsonObject)
    assert sample_json_obj.string == sample_json["string"]
    assert sample_json_obj.number == sample_json["number"]
    assert isinstance(sample_json_obj.object, digest.JsonObject)
    assert sample_json_obj.object.key1 == sample_dict["key1"]
    innerKey1_val = sample_dict["nestedObject"]["innerKey1"]
    assert sample_json_obj.object.nestedObject.innerKey1 == innerKey1_val


def test_promote_named_objects(sample_json):
    """Test the promote_named_objects routine."""

    class ExampleJsonObjectClass(digest.JsonObject):
        def __init__(self, /, **kwargs):
            super().__init__(**kwargs)
            self.keynum = len(self.__dict__.keys()) - 1

    sample_obj_map = {
        "object": ExampleJsonObjectClass,
        "array": ExampleJsonObjectClass,
        "nestedObject": digest.JsonObject,
    }

    sample_raw = json.dumps(sample_json)
    sample_json_obj = json.loads(
        sample_raw,
        object_hook=lambda x: digest.promote_named_objects(x, sample_obj_map),
    )

    assert isinstance(sample_json_obj, digest.JsonObject)
    assert not isinstance(sample_json_obj, ExampleJsonObjectClass)

    assert isinstance(sample_json_obj.object, digest.JsonObject)
    assert isinstance(sample_json_obj.object, ExampleJsonObjectClass)
    assert hasattr(sample_json_obj.object, "keynum")
    sample_dict = sample_json["object"]
    innerKey1_val = sample_dict["nestedObject"]["innerKey1"]
    assert sample_json_obj.object.nestedObject.innerKey1 == innerKey1_val

    sample_array = sample_json["array"]
    for i, value in enumerate(sample_array):
        if isinstance(value, dict):
            should_be_promoted = sample_json_obj.array[i]
            assert isinstance(should_be_promoted, ExampleJsonObjectClass)
        else:
            assert sample_array[i] == sample_json_obj.array[i]
