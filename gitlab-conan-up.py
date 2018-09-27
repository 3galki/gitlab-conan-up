#!/Library/Frameworks/Python.framework/Versions/3.6/bin/python3
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from termcolor import colored
from urllib.parse import quote_plus
import urllib3
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed


class Gitlab:
    class Project:
        def __init__(self, gitlab, info, branch, conanfile, depends):
            self._gitlab = gitlab
            self.info = info
            self.conanfile = conanfile
            self.depends = depends
            self.branch = branch

        @property
        def name(self):
            return None

        def not_depends(self, projects):
            return next((False for depend in self.depends if next((True for base in projects if base.name == depend.split('@')[0]), False)), True)

        def update(self):
            comment = self._gitlab.update_versions(self, "\n{name}/{version}@{tail}")
            if len(comment) > 0:
                comment = 'Auto updating dependencies.' + comment
                return self._gitlab.update(
                    self.info,
                    self.branch,
                    'conanfile.txt',
                    self.conanfile,
                    'version/' + hashlib.md5(self.conanfile.encode()).hexdigest(),
                    comment
                )
            return False

        def up(self):
            print('Update: %s' % self.info['name'])
            self.update()
            return self

    class Package(Project):
        def __init__(self, gitlab, info, branch, conanfile, depends, name, version):
            super().__init__(gitlab, info, branch, conanfile, depends)
            self._name = name
            self._version = version

        @property
        def name(self):
            return self._name

        def update(self):
            comment = self._gitlab.update_versions(self, '"{name}/{version}@{tail}')
            comment += self._gitlab.update_versions(self, "'{name}/{version}@{tail}")
            if len(comment) > 0:
                version = re.search(r'''^\s+version\s*=\s*['"]([^'"]*).*$''', self.conanfile, re.MULTILINE)
                if version and version.group(1) == self._version:
                    # TODO (greed) Remove ispsystem depends
                    values = self._gitlab.max_version(self._name + '@ispsystem/' + self.branch, self._version).split('.')
                    while len(values) < 3:
                        values.append('0')
                    values[-1] = str(int(values[-1]) + 1)
                    self._version = '.'.join(values)
                    self.conanfile = self.conanfile[0:version.start(1)] + self._version + self.conanfile[version.end(1):]
                    comment = 'Auto updating to version {version}'.format(version=self._version) + comment
                    if not self._gitlab.update(self.info, self.branch, 'conanfile.py', self.conanfile, 'version/' + self._version, comment):
                        print(colored('FAILED TO UPDATE {name}/{branch}', 'red').
                              format(name=self._name, branch=self.branch))
                        return
            self._gitlab.set_version(self._name + '@ispsystem/' + self.branch, self._version)

    def __init__(self, url, token, dry_run):
        self._url = url
        self._token = token
        self._pattern = re.compile('([^/]*)/([^@]*)@(.*)')
        self._branch_pattern = re.compile('^rc[0-9]+$')

        self._versions = {}
        self._dry_run = dry_run
        urllib3.disable_warnings()

    def update_versions(self, project: Project, pattern):
        comment = ''
        for name, value in project.depends.items():
            nm = name.split('@', 2)
            tmp = project.conanfile.replace(
                pattern.format(name=nm[0], tail=nm[1], version=value),
                pattern.format(name=nm[0], tail=nm[1], version=self._versions[name])
            )
            if tmp != project.conanfile:
                project.conanfile = tmp
                comment += '\nupdate {name} {old} => {new}'.format(name=name, old=value, new=self._versions[name])
        return comment

    def set_version(self, name, value):
        self._versions[name] = value

    def get_projects(self, group):
        http = urllib3.PoolManager()
        r = http.request(
            method='GET',
            url='https://{gitlab}/api/v4/groups/{id}/projects?per_page=100'.format(id=quote_plus(group), gitlab=self._url),
            headers={'Private-Token': self._token}
        )
        return json.loads(r.data.decode())

    def get_branches(self, project):
        http = urllib3.PoolManager()
        r = http.request(
            method='GET',
            url='https://{gitlab}/api/v4/projects/{id}/repository/branches?per_page=100'.format(id=project, gitlab=self._url),
            headers={'Private-Token': self._token},
        )
        if r.status != 200:
            return None
        data = json.loads(r.data.decode())
        return (branch['name'] for branch in data if branch['name'] == 'master' or self._branch_pattern.match(branch['name']))

    def get_file(self, project, branch, file):
        http = urllib3.PoolManager()
        r = http.request(
            method='GET',
            url='https://{gitlab}/api/v4/projects/{id}/repository/files/{file}/raw?ref={branch}'.
                format(id=project, gitlab=self._url, file=file, branch=branch),
            headers={'Private-Token': self._token},
        )
        if r.status != 200:
            return None
        return r.data.decode()

    @staticmethod
    def _version_less(first, second):
        if first == second:
            return False
        f = first.split('.')
        s = second.split('.')
        for i in range(min(len(f), len(s))):
            if f[i] == s[i]:
                continue
            if f[i].isdecimal() and s[i].isdecimal():
                return int(f[i]) < int(s[i])
            else:
                return f[i] < s[i]
        return len(f) < len(s)

    def max_version(self, name, version):
        if name in self._versions:
            if self._version_less(self._versions[name], version):
                return version
            return self._versions[name]
        return version

    def read_deps(self, prefix, stream):
        deps = {}
        for line in stream:
            data = line.decode().strip()
            res = self._pattern.search(data)
            if res:
                name = res.group(1) + '@' + res.group(3)
                self.set_version(name=name, value=self.max_version(name=name, version=res.group(2)))
                deps[name] = res.group(2)
                print("    {prefix}\t{version:<10} {name}".format(prefix=prefix, version=res.group(2), name=name))
        return deps

    def make_project(self, project, branch, data):
        with tempfile.TemporaryDirectory() as folder:
            with open(os.path.join(folder, 'conanfile.txt'), 'wb') as fd:
                fd.write(data.encode('utf-8'))
            info = subprocess.Popen(['conan', 'info', '-n', 'None', folder],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            for line in info.stdout:
                version = line.decode().strip()
                if version == 'PROJECT':
                    return self.Project(self,
                                        project,
                                        branch,
                                        data,
                                        self.read_deps(project['name'] + '/' + branch, info.stdout)
                                        )
            return None

    def make_package(self, project, branch, data):
        with tempfile.TemporaryDirectory() as folder:
            with open(os.path.join(folder, 'conanfile.py'), 'wb') as fd:
                fd.write(data.encode('utf-8'))
            info = subprocess.Popen(['conan', 'info', '-n', 'None', folder],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            output = ''
            for line in info.stdout:
                version = line.decode().strip()
                output = '\n'.join([output, version])
                if version.endswith('@PROJECT'):
                    version = self._pattern.search(version)
                    return self.Package(self,
                                        project,
                                        branch,
                                        data,
                                        self.read_deps(project['name'] + '/' + branch, info.stdout),
                                        version.group(1),
                                        version.group(2)
                                        )
            print(colored('FAILED TO GET CONAN INFO project {project} branch {branch}\n\n{output}','red').
                  format(project=project['name'], branch=branch, output=output))
            return None

    def get_conan_versions(self, project, branch):
        print('Check project {name} branch {branch}'.format(name=project['name'], branch=branch))
        data = self.get_file(str(project['id']), branch, 'conanfile.py')
        if data is not None:
            return self.make_package(project, branch, data)
        data = self.get_file(str(project['id']), branch, 'conanfile.txt')
        if data is not None:
            return self.make_project(project, branch, data)
        print(colored('Conanfile not found in project {name} branch {branch}', 'yellow').
              format(name=project['name'], branch=branch))
        return None

    def update(self, info, src_branch, filename, content, branch, comment):
        print((colored('UPDATE "{project}/{branch}"', 'green') + ' with comment: {comment}').
              format(project=info['name'], comment=comment, branch=src_branch))
        if self._dry_run:
            return True
        http = urllib3.PoolManager()

        r = http.request(
            method='PUT',
            url='https://{gitlab}/api/v4/projects/{id}/repository/files/{file_path}'.
                format(id=info['id'], file_path=quote_plus(filename), gitlab=self._url),
            headers={'Private-Token': self._token},
            fields={
                'branch': branch,
                'start_branch': src_branch,
                'content': content,
                'commit_message': comment
            }
        )
        if r.status != 200:
            print(colored('Error: %s', 'red') % r.data)
            return False

        r = http.request(
            method='POST',
            url='https://{gitlab}/api/v4/projects/{id}/merge_requests'.format(id=info['id'], gitlab=self._url),
            headers={'Private-Token': self._token},
            fields={
                'source_branch': branch,
                'target_branch': src_branch,
                'title': comment,
                'remove_source_branch': 'true'
            }
        )
        if r.status != 201:
            print(colored('Error: %s', 'red') % r.data)
            return False

        result = json.loads(r.data.decode())
        if not self.wait_pipeline(http, info['id'], result['sha']):
            return False

        r = http.request(
            method='PUT',
            url='https://{gitlab}/api/v4/projects/{id}/merge_requests/{merge_iid}/merge'.
                format(id=info['id'], merge_iid=result["iid"], gitlab=self._url),
            headers={'Private-Token': self._token}
        )
        if r.status != 200:
            print(colored('Error: %s', 'red') % r.data)
            return False

        result = json.loads(r.data.decode())
        return self.wait_pipeline(http, info['id'], result['merge_commit_sha'])

    def wait_pipeline(self, http, project, sha):
        for _ in range(10):
            r1 = http.request(
                method='GET',
                url='https://{gitlab}/api/v4/projects/{id}/pipelines'.format(id=project, gitlab=self._url),
                headers={'Private-Token': self._token}
            )
            if r1.status != 200:
                return False
            pipelines = json.loads(r1.data.decode())
            pipeline_id, status = next(
                ((pipeline['id'], pipeline['status']) for pipeline in pipelines if pipeline['sha'] == sha),
                (None, None))
            if pipeline_id is not None:
                break
            print('\twaiting pipeline for sha {sha}'.format(sha=sha))
            time.sleep(15)
        if pipeline_id is None:
            print(colored('Error %s', 'red') % json.dumps(pipelines))
            return False

        while status == 'running' or status == 'pending' or status == 'created':
            r1 = http.request(
                method='GET',
                url='https://{gitlab}/api/v4/projects/{id}/pipelines/{pipeline_id}'.
                    format(id=project, pipeline_id=pipeline_id, gitlab=self._url),
                headers={'Private-Token': self._token}
            )
            if r1.status != 200:
                return False
            tmp = json.loads(r1.data.decode())
            status = tmp['status']
            print('\twaiting pipeline {pipeline} for sha {sha}'.format(sha=sha, pipeline=pipeline_id))
            time.sleep(15)
        print(colored('\tpipeline {pipeline} status {status}', 'green' if status == 'success' else 'red').
              format(status=status, pipeline=pipeline_id))
        return status == 'success'

sys.setdefaultencoding('utf8')
parser = argparse.ArgumentParser(description='Conan package version updater')
parser.add_argument('--gitlab', help='GitLab URL', required=True)
parser.add_argument('--gitlab-token', help='GitLab private token', required=True)
parser.add_argument('--dry-run', help='Report versions but do not update anything', const=True, default=False, action='store_const')
parser.add_argument('groups', help='gitlab goup list to update. All conan packages in this group will be updated', nargs='+')
args = parser.parse_args()

gitlab = Gitlab(args.gitlab, args.gitlab_token, args.dry_run)
for group in args.groups:
    gitlab_projects = gitlab.get_projects(group)
    with ThreadPoolExecutor(max_workers=4) as executor:
        pkgs = (executor.submit(Gitlab.get_conan_versions, gitlab, project, branch)
                for project in gitlab_projects
                for branch in gitlab.get_branches(str(project['id']))
                )
        projects = [future.result() for future in as_completed(pkgs) if future.result() is not None]
        while len(projects) > 0:
            print(colored('=' * 30, 'blue'))
            to_update = [project for project in projects if project.not_depends(projects)]
            if len(to_update) == 0:
                exit('Loop detected')
            pkgs = (executor.submit(Gitlab.Project.up, project) for project in to_update)
            for future in as_completed(pkgs):
                project = future.result()
                projects.remove(project)
