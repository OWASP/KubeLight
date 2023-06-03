import os
import stat
import unittest
from tempfile import TemporaryDirectory
from bench.utils import FileOps

class FileOpsCISTestCase(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for testing
        self.temp_dir = TemporaryDirectory()
        self.test_dir = self.temp_dir.name

        # Create the directory structure for testing
        os.makedirs(os.path.join(self.test_dir, 'kube-apiserver'))
        os.makedirs(os.path.join(self.test_dir, 'kube-controller-manager'))
        os.makedirs(os.path.join(self.test_dir, 'kubelet'))

        # Set permissions and ownership for the test files and directories
        os.chmod(os.path.join(self.test_dir, 'kube-apiserver'), stat.S_IRWXU)
        os.chmod(os.path.join(self.test_dir, 'kube-controller-manager'), stat.S_IRGRP)
        os.chmod(os.path.join(self.test_dir, 'kubelet'), stat.S_IROTH)
        os.chown(os.path.join(self.test_dir, 'kube-apiserver'), os.getuid(), os.getgid())
        os.chown(os.path.join(self.test_dir, 'kube-controller-manager'), os.getuid(), os.getgid())
        os.chown(os.path.join(self.test_dir, 'kubelet'), os.getuid(), os.getgid())

        # Initialize FileOps with test directories
        self.file_ops = FileOps(dirs=[os.path.join(self.test_dir, 'kube-apiserver'),
                                      os.path.join(self.test_dir, 'kube-controller-manager'),
                                      os.path.join(self.test_dir, 'kubelet')])

    def tearDown(self):
        # Clean up the temporary directory
        self.temp_dir.cleanup()

    def test_less_permission(self):
        # Test the less_permission method
        threshold = stat.S_IRGRP
        result = self.file_ops.less_permission(threshold)

        # Assert that kube-apiserver has less permission than the threshold
        self.assertTrue(result[0][os.path.join(self.test_dir, 'kube-apiserver')])

        # Assert that kube-controller-manager does not have less permission than the threshold
        self.assertFalse(result[1][os.path.join(self.test_dir, 'kube-controller-manager')])

        # Assert that kubelet does not have less permission than the threshold
        self.assertFalse(result[2][os.path.join(self.test_dir, 'kubelet')])

    def test_match_owner(self):
        # Test the match_owner method
        user = os.getlogin()
        group = os.getlogin()
        result = self.file_ops.match_owner(user, group)

        # Assert that kube-apiserver, kube-controller-manager, and kubelet have matching ownership
        self.assertTrue(result[0][os.path.join(self.test_dir, 'kube-apiserver')])
        self.assertTrue(result[1][os.path.join(self.test_dir, 'kube-controller-manager')])
        self.assertTrue(result[2][os.path.join(self.test_dir, 'kubelet')])

if __name__ == '__main__':
    unittest.main()
