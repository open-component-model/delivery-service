import datetime

import pytest

import sprints.model as sm
import sprints.util as su


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_sprint(
    name: str,
    end_date: datetime.date,
) -> sm.Sprint:
    return sm.Sprint(
        name=name,
        dates=[
            sm.SprintDate(
                name=sm.SprintNames.END_DATE,
                display_name='End Date',
                value=end_date,
            ),
        ],
    )


# ---------------------------------------------------------------------------
# SprintsConfiguration.__post_init__
# ---------------------------------------------------------------------------


class TestSprintsConfigurationPostInit:
    def test_dict_sprint_is_converted_to_sprint_object(self):
        cfg = sm.SprintsConfiguration(
            meta=None,
            sprints=[{'name': 'S1', 'end_date': '2024-01-14'}],
        )

        assert len(cfg.sprints) == 1
        sprint = cfg.sprints[0]
        assert isinstance(sprint, sm.Sprint)
        assert sprint.name == 'S1'

    def test_end_date_string_is_parsed_correctly(self):
        cfg = sm.SprintsConfiguration(
            meta=None,
            sprints=[{'name': 'S1', 'end_date': '2024-03-22'}],
        )

        end_date = cfg.sprints[0].find_sprint_date(sm.SprintNames.END_DATE).value
        assert end_date == datetime.date(2024, 3, 22)

    def test_end_date_with_time_component_is_parsed_correctly(self):
        cfg = sm.SprintsConfiguration(
            meta=None,
            sprints=[{'name': 'S1', 'end_date': '2024-03-22T12:00:00'}],
        )

        end_date = cfg.sprints[0].find_sprint_date(sm.SprintNames.END_DATE).value
        assert end_date == datetime.date(2024, 3, 22)

    def test_offsets_from_meta_are_applied(self):
        meta = sm.SprintMetadata(
            offsets=[
                sm.SprintOffsets(name='freeze', display_name='Freeze', offset_days=-3),
                sm.SprintOffsets(name='deploy', display_name='Deploy', offset_days=1),
            ],
        )
        cfg = sm.SprintsConfiguration(
            meta=meta,
            sprints=[{'name': 'S1', 'end_date': '2024-03-22'}],
        )

        sprint = cfg.sprints[0]
        # end_date itself is always present
        assert sprint.find_sprint_date(sm.SprintNames.END_DATE).value == datetime.date(2024, 3, 22)
        # freeze = end_date - 3 days
        assert sprint.find_sprint_date('freeze').value == datetime.date(2024, 3, 19)
        # deploy = end_date + 1 day
        assert sprint.find_sprint_date('deploy').value == datetime.date(2024, 3, 23)

    def test_no_meta_produces_only_end_date(self):
        cfg = sm.SprintsConfiguration(
            meta=None,
            sprints=[{'name': 'S1', 'end_date': '2024-03-22'}],
        )

        assert len(cfg.sprints[0].dates) == 1

    def test_multiple_dict_sprints_are_all_converted(self):
        cfg = sm.SprintsConfiguration(
            meta=None,
            sprints=[
                {'name': 'S1', 'end_date': '2024-01-14'},
                {'name': 'S2', 'end_date': '2024-01-28'},
                {'name': 'S3', 'end_date': '2024-02-11'},
            ],
        )

        assert len(cfg.sprints) == 3
        assert [s.name for s in cfg.sprints] == ['S1', 'S2', 'S3']

    def test_invalid_sprint_type_raises_type_error(self):
        with pytest.raises(TypeError):
            sm.SprintsConfiguration(
                meta=None,
                sprints=['not-a-sprint'],
            )

    def test_mixed_sprint_objects_and_dicts_are_all_preserved(self):
        existing_sprint = _make_sprint('S1', datetime.date(2024, 1, 14))
        cfg = sm.SprintsConfiguration(
            meta=None,
            sprints=[
                existing_sprint,
                {'name': 'S2', 'end_date': '2024-01-28'},
            ],
        )

        assert len(cfg.sprints) == 2
        assert all(isinstance(s, sm.Sprint) for s in cfg.sprints)
        assert cfg.sprints[0].name == 'S1'
        assert cfg.sprints[1].name == 'S2'


# ---------------------------------------------------------------------------
# Sprint.find_sprint_date
# ---------------------------------------------------------------------------


class TestFindSprintDate:
    def test_returns_matching_sprint_date(self):
        sprint = _make_sprint('S1', datetime.date(2024, 1, 14))
        result = sprint.find_sprint_date(sm.SprintNames.END_DATE)
        assert result.value == datetime.date(2024, 1, 14)

    def test_raises_when_name_not_found_and_absent_not_ok(self):
        sprint = _make_sprint('S1', datetime.date(2024, 1, 14))
        with pytest.raises(ValueError):
            sprint.find_sprint_date('nonexistent')

    def test_returns_none_when_name_not_found_and_absent_ok(self):
        sprint = _make_sprint('S1', datetime.date(2024, 1, 14))
        result = sprint.find_sprint_date('nonexistent', absent_ok=True)
        assert result is None

    def test_raises_when_duplicates_exist(self):
        with pytest.raises(ValueError):
            sm.Sprint(
                name='S1',
                dates=[
                    sm.SprintDate(name='foo', display_name=None, value=datetime.date(2024, 1, 1)),
                    sm.SprintDate(name='foo', display_name=None, value=datetime.date(2024, 1, 2)),
                ],
            )


# ---------------------------------------------------------------------------
# Sprint.__eq__ (__hash__)
# ---------------------------------------------------------------------------


class TestSprintEq:
    def test_sprints_with_same_name_are_equal(self):
        s1 = _make_sprint('S1', datetime.date(2024, 1, 14))
        s2 = _make_sprint('S1', datetime.date(2024, 6, 1))
        assert s1 == s2

    def test_sprints_with_different_names_are_not_equal(self):
        s1 = _make_sprint('S1', datetime.date(2024, 1, 14))
        s2 = _make_sprint('S2', datetime.date(2024, 1, 14))
        assert s1 != s2

    def test_sprint_found_in_list_by_name(self):
        sprints = [
            _make_sprint('S1', datetime.date(2024, 1, 14)),
            _make_sprint('S2', datetime.date(2024, 1, 28)),
        ]
        assert _make_sprint('S1', datetime.date(2024, 6, 1)) in sprints

    def test_sprint_not_found_in_list_when_name_absent(self):
        sprints = [
            _make_sprint('S1', datetime.date(2024, 1, 14)),
            _make_sprint('S2', datetime.date(2024, 1, 28)),
        ]
        assert _make_sprint('S3', datetime.date(2024, 1, 14)) not in sprints

    def test_sprint_not_equal_to_non_sprint(self):
        sprint = _make_sprint('S1', datetime.date(2024, 1, 14))
        assert sprint != 'S1'
        assert sprint != 42


# ---------------------------------------------------------------------------
# find_sprint_for_ref_date
# ---------------------------------------------------------------------------


class TestFindSprintForRefDate:
    def _sprints(self):
        return [
            _make_sprint('S1', datetime.date(2024, 1, 14)),
            _make_sprint('S2', datetime.date(2024, 1, 28)),
            _make_sprint('S3', datetime.date(2024, 2, 11)),
        ]

    def test_returns_sprint_whose_end_date_equals_ref_date(self):
        result = su.find_sprint_for_ref_date(
            ref_date=datetime.date(2024, 1, 14),
            sprints=self._sprints(),
        )
        assert result.name == 'S1'

    def test_returns_first_sprint_after_ref_date(self):
        result = su.find_sprint_for_ref_date(
            ref_date=datetime.date(2024, 1, 15),
            sprints=self._sprints(),
        )
        assert result.name == 'S2'

    def test_returns_last_sprint_when_ref_date_is_after_all_end_dates(self):
        result = su.find_sprint_for_ref_date(
            ref_date=datetime.date(2024, 12, 31),
            sprints=self._sprints(),
        )
        assert result.name == 'S3'

    def test_positive_offset_returns_next_sprint(self):
        result = su.find_sprint_for_ref_date(
            ref_date=datetime.date(2024, 1, 14),
            sprints=self._sprints(),
            sprint_assignment_offset=1,
        )
        assert result.name == 'S2'

    def test_negative_offset_returns_previous_sprint(self):
        result = su.find_sprint_for_ref_date(
            ref_date=datetime.date(2024, 1, 28),
            sprints=self._sprints(),
            sprint_assignment_offset=-1,
        )
        assert result.name == 'S1'

    def test_offset_clamps_to_first_sprint_when_underflow(self):
        result = su.find_sprint_for_ref_date(
            ref_date=datetime.date(2024, 1, 14),
            sprints=self._sprints(),
            sprint_assignment_offset=-5,
        )
        assert result.name == 'S1'

    def test_offset_clamps_to_last_sprint_when_overflow(self):
        result = su.find_sprint_for_ref_date(
            ref_date=datetime.date(2024, 1, 14),
            sprints=self._sprints(),
            sprint_assignment_offset=99,
        )
        assert result.name == 'S3'

    def test_returns_none_when_ref_date_is_none(self):
        result = su.find_sprint_for_ref_date(
            ref_date=None,
            sprints=self._sprints(),
        )
        assert result is None

    def test_returns_none_when_sprints_is_none(self):
        result = su.find_sprint_for_ref_date(
            ref_date=datetime.date(2024, 1, 14),
            sprints=None,
        )
        assert result is None

    def test_returns_none_when_sprints_is_empty(self):
        result = su.find_sprint_for_ref_date(
            ref_date=datetime.date(2024, 1, 14),
            sprints=[],
        )
        assert result is None

    def test_sorts_unsorted_input_sprints_before_searching(self):
        sprints = [
            _make_sprint('S3', datetime.date(2024, 2, 11)),
            _make_sprint('S1', datetime.date(2024, 1, 14)),
            _make_sprint('S2', datetime.date(2024, 1, 28)),
        ]
        result = su.find_sprint_for_ref_date(
            ref_date=datetime.date(2024, 1, 15),
            sprints=sprints,
        )
        assert result.name == 'S2'
