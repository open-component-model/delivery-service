import datetime

import dora


def test_next_older_month():
    assert (
        datetime.datetime(2024, 9, 1, tzinfo=datetime.UTC)
        == dora.next_older_month(datetime.datetime(2024, 10, 4))
    )

    assert (
        datetime.datetime(1999, 12, 1, tzinfo=datetime.UTC)
        == dora.next_older_month(datetime.datetime(2000, 1, 10))
    )
