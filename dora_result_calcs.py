import collections
import dataclasses
import datetime
import statistics


@dataclasses.dataclass(frozen=True)
class ReturnCommitObject:
    commitSha: str
    commitDate: datetime.datetime
    deploymentDate: datetime.datetime
    leadTime: datetime.timedelta
    url: str

    def to_dict(self):
        return {
            'commitSha': self.commitSha,
            'commitDate': self.commitDate.isoformat(),
            'deploymentDate': self.deploymentDate.isoformat(),
            'leadTime': self.leadTime.total_seconds(),
            'url': self.url,
        }


@dataclasses.dataclass(frozen=True)
class ReturnDeploymentObject:
    targetComponentVersionNew: str
    targetComponentVersionOld: str
    deployedComponentVersion: str
    oldComponentVersion: str
    deploymentDate: datetime.datetime
    commits: list[ReturnCommitObject]

    def to_dict(self):
        return {
            'targetComponentVersionNew': self.targetComponentVersionNew,
            'targetComponentVersionOld': self.targetComponentVersionOld,
            'deployedComponentVersion': self.deployedComponentVersion,
            'oldComponentVersion': self.oldComponentVersion,
            'deploymentDate': self.deploymentDate.isoformat(),
            'commits': [commit.to_dict() for commit in self.commits],
        }


@dataclasses.dataclass(frozen=True)
class ReturnObject:
    targetComponentName: str
    timePeriod: float
    componentName: str
    medianDeploymentFrequency: float
    medianLeadTime: float
    deploymentsPerMonth: dict
    deploymentsPerWeek: dict
    deploymentsPerDay: dict
    leadTimePerMonth: dict
    leadTimePerWeek: dict
    leadTimePerDay: dict
    deployments: list[ReturnDeploymentObject]

    def to_dict(self):
        return {
            'targetComponentName': self.targetComponentName,
            'timePeriod': self.timePeriod,
            'componentName': self.componentName,
            'medianDeploymentFrequency': self.medianDeploymentFrequency,
            'medianLeadTime': self.medianLeadTime,
            'deploymentsPerMonth': self.deploymentsPerMonth,
            'deploymentsPerWeek': self.deploymentsPerWeek,
            'deploymentsPerDay': self.deploymentsPerDay,
            'leadTimePerMonth': {k: v for k, v in self.leadTimePerMonth.items()},
            'leadTimePerWeek': {k: v for k, v in self.leadTimePerWeek.items()},
            'leadTimePerDay': {k: v for k, v in self.leadTimePerDay.items()},
            'deployents': [deployment.to_dict() for deployment in self.deployments],
        }


def calc_deployments_per(deployment_objects: list[ReturnDeploymentObject]):
    deployments_per_month = collections.defaultdict(int)
    deployments_per_week = collections.defaultdict(int)
    deployments_per_day = collections.defaultdict(int)

    for deployment in deployment_objects:

        # First day of the month
        first_day_month = deployment.deploymentDate.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_key = first_day_month.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        deployments_per_month[month_key] += 1

        # First day of the week
        first_day_week = deployment.deploymentDate - datetime.timedelta(
            days=deployment.deploymentDate.weekday()
        )
        week_key = first_day_week.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        deployments_per_week[week_key] += 1

        # Exact day
        day_key = deployment.deploymentDate.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        deployments_per_day[day_key] += 1

    return {
        'deploymentsPerMonth': dict(deployments_per_month),
        'deploymentsPerWeek': dict(deployments_per_week),
        'deploymentsPerDay': dict(deployments_per_day)
    }


def calc_lead_time_per(deployment_objects: list[ReturnDeploymentObject]):
    lead_times_per_month = collections.defaultdict(list)
    lead_times_per_week = collections.defaultdict(list)
    lead_times_per_day = collections.defaultdict(list)

    for deployment in deployment_objects:

        # First day of the month
        first_day_month = deployment.deploymentDate.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_key = first_day_month.isoformat()

        # First day of the week
        first_day_week = deployment.deploymentDate - datetime.timedelta(
            days=deployment.deploymentDate.weekday()
        )
        week_key = first_day_week.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

        # Exact day
        day_key = deployment.deploymentDate.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

        for commit in deployment.commits:
            lead_times_per_month[month_key].append(commit.leadTime.total_seconds())
            lead_times_per_week[week_key].append(commit.leadTime.total_seconds())
            lead_times_per_day[day_key].append(commit.leadTime.total_seconds())

    median_lead_time_per_month = {k: statistics.median(v) for k, v in lead_times_per_month.items()}
    median_lead_time_per_week = {k: statistics.median(v) for k, v in lead_times_per_week.items()}
    median_lead_time_per_day = {k: statistics.median(v) for k, v in lead_times_per_day.items()}

    return {
        'medianLeadTimePerMonth': median_lead_time_per_month,
        'medianLeadTimePerWeek': median_lead_time_per_week,
        'medianLeadTimePerDay': median_lead_time_per_day,
    }
