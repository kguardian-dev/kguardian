import { useState, useEffect, useRef } from 'react';
import type { PodNodeData } from '../../types';
import type { SeccompProfile, SeccompSyscall, SeccompAction } from '../../types/seccompProfile';
import { generateSeccompProfile } from '../../utils/seccompProfileGenerator';
import { isValidSyscall } from '../../utils/syscalls';

interface UseSeccompProfileEditorProps {
  pod: PodNodeData | null;
  isOpen: boolean;
}

export const useSeccompProfileEditor = ({ pod, isOpen }: UseSeccompProfileEditorProps) => {
  const [seccompProfile, setSeccompProfile] = useState<SeccompProfile | null>(null);
  const [isSyscallsExpanded, setIsSyscallsExpanded] = useState(true);
  const [syscallErrors, setSyscallErrors] = useState<{ [key: number]: string }>({});

  // Track which pod we've generated profile for to avoid regeneration
  const lastGeneratedPodId = useRef<string | null>(null);

  useEffect(() => {
    const currentPodId = pod?.id || null;

    // Only generate if we have a pod and haven't generated for this pod yet
    if (isOpen && pod && currentPodId !== lastGeneratedPodId.current) {
      lastGeneratedPodId.current = currentPodId;
      const generatedProfile = generateSeccompProfile(pod);
      setSeccompProfile(generatedProfile);
    }
  }, [isOpen, pod]);

  const addSyscallRule = () => {
    if (!seccompProfile) return;
    const newRule: SeccompSyscall = {
      names: [],
      action: 'SCMP_ACT_ALLOW',
    };
    setSeccompProfile({
      ...seccompProfile,
      syscalls: [...(seccompProfile.syscalls || []), newRule],
    });
  };

  const removeSyscallRule = (index: number) => {
    if (!seccompProfile) return;
    setSeccompProfile({
      ...seccompProfile,
      syscalls: seccompProfile.syscalls?.filter((_, i) => i !== index),
    });
  };

  const addSyscallToRule = (ruleIndex: number, syscall: string): boolean => {
    if (!seccompProfile || !syscall.trim()) return false;

    const trimmedSyscall = syscall.trim().toLowerCase();

    // Validate syscall name
    if (!isValidSyscall(trimmedSyscall)) {
      setSyscallErrors({
        ...syscallErrors,
        [ruleIndex]: `"${trimmedSyscall}" is not a valid Linux syscall name`,
      });
      return false;
    }

    // Check if syscall already exists in this rule
    const rule = seccompProfile.syscalls?.[ruleIndex];
    if (rule && rule.names.includes(trimmedSyscall)) {
      setSyscallErrors({
        ...syscallErrors,
        [ruleIndex]: `"${trimmedSyscall}" is already in this rule`,
      });
      return false;
    }

    // Clear error and add syscall
    setSyscallErrors({
      ...syscallErrors,
      [ruleIndex]: '',
    });

    setSeccompProfile({
      ...seccompProfile,
      syscalls: seccompProfile.syscalls?.map((rule, i) =>
        i === ruleIndex
          ? { ...rule, names: [...rule.names, trimmedSyscall] }
          : rule
      ),
    });

    return true;
  };

  const removeSyscallFromRule = (ruleIndex: number, syscallIndex: number) => {
    if (!seccompProfile) return;
    setSeccompProfile({
      ...seccompProfile,
      syscalls: seccompProfile.syscalls?.map((rule, i) =>
        i === ruleIndex
          ? { ...rule, names: rule.names.filter((_, j) => j !== syscallIndex) }
          : rule
      ),
    });
  };

  const updateSyscallAction = (ruleIndex: number, action: SeccompAction) => {
    if (!seccompProfile) return;
    setSeccompProfile({
      ...seccompProfile,
      syscalls: seccompProfile.syscalls?.map((rule, i) =>
        i === ruleIndex ? { ...rule, action } : rule
      ),
    });
  };

  const updateDefaultAction = (action: SeccompAction) => {
    if (!seccompProfile) return;
    setSeccompProfile({
      ...seccompProfile,
      defaultAction: action,
    });
  };

  const toggleArchitecture = (arch: string) => {
    if (!seccompProfile) return;
    const currentArchs = seccompProfile.architectures || [];
    const hasArch = currentArchs.includes(arch);

    setSeccompProfile({
      ...seccompProfile,
      architectures: hasArch
        ? currentArchs.filter(a => a !== arch)
        : [...currentArchs, arch],
    });
  };

  const clearSyscallError = (ruleIndex: number) => {
    setSyscallErrors({
      ...syscallErrors,
      [ruleIndex]: '',
    });
  };

  return {
    seccompProfile,
    setSeccompProfile,
    isSyscallsExpanded,
    setIsSyscallsExpanded,
    syscallErrors,
    addSyscallRule,
    removeSyscallRule,
    addSyscallToRule,
    removeSyscallFromRule,
    updateSyscallAction,
    updateDefaultAction,
    toggleArchitecture,
    clearSyscallError,
  };
};
