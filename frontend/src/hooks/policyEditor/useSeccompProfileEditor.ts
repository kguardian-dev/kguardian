import { useState, useEffect, useRef } from 'react';
import type { PodNodeData } from '../../types';
import type { SeccompProfile, SeccompSyscall, SeccompAction } from '../../types/seccompProfile';
import { generateSeccompProfile, validateSeccompProfile } from '../../utils/seccompProfileGenerator';
import { isValidSyscall } from '../../utils/syscalls';

/**
 * A profile to edit that did NOT come from a pod's observed syscalls — e.g.
 * the broker's effective per-workload profile in the override editor. `key`
 * identifies the loaded revision (workload + revision + hash); when it changes
 * the editor re-seeds, which is how a reload after a 409 lands.
 */
export interface SeccompEditorSeed {
  key: string;
  profile: SeccompProfile;
}

interface UseSeccompProfileEditorProps {
  pod: PodNodeData | null;
  isOpen: boolean;
  /** Takes precedence over `pod` when set. */
  seed?: SeccompEditorSeed | null;
}

export const useSeccompProfileEditor = ({ pod, isOpen, seed = null }: UseSeccompProfileEditorProps) => {
  const [seccompProfile, setSeccompProfile] = useState<SeccompProfile | null>(null);
  const [isSyscallsExpanded, setIsSyscallsExpanded] = useState(true);
  const [syscallErrors, setSyscallErrors] = useState<{ [key: number]: string }>({});

  // Track which source (pod id or seed key) the current profile came from so
  // the user's edits survive re-renders and only a genuinely new source resets.
  const lastGeneratedPodId = useRef<string | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    if (seed) {
      const seedId = `seed:${seed.key}`;
      if (seedId !== lastGeneratedPodId.current) {
        lastGeneratedPodId.current = seedId;
        setSeccompProfile(structuredClone(seed.profile));
      }
      return;
    }
    const currentPodId = pod?.id || null;

    // Only generate if we have a pod and haven't generated for this pod yet
    if (pod && currentPodId !== lastGeneratedPodId.current) {
      lastGeneratedPodId.current = currentPodId;
      const generatedProfile = generateSeccompProfile(pod);
      setSeccompProfile(generatedProfile);
    }
  }, [isOpen, pod, seed]);

  /** Discard edits and return to the seed / regenerate from the pod. */
  const resetProfile = () => {
    if (seed) {
      setSeccompProfile(structuredClone(seed.profile));
    } else if (pod) {
      setSeccompProfile(generateSeccompProfile(pod));
    }
    setSyscallErrors({});
  };

  // Derived, non-fatal warning when the current profile isn't directly usable
  // (e.g. an unrecognized CPU arch → no architectures selected). Derived from
  // the profile rather than stored, so it live-updates as the user edits and
  // clears itself once they pick an architecture / add a syscall rule.
  let generationWarning: string | null = null;
  if (seccompProfile) {
    try {
      validateSeccompProfile(seccompProfile);
    } catch (e) {
      generationWarning = e instanceof Error ? e.message : String(e);
    }
  }

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
    resetProfile,
    generationWarning,
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
