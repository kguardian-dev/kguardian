import { useState } from 'react';
import { getSyscallSuggestions } from '../../utils/syscalls';

export const useSyscallAutocomplete = () => {
  const [syscallInputValues, setSyscallInputValues] = useState<{ [key: number]: string }>({});
  const [syscallSuggestions, setSyscallSuggestions] = useState<{ [key: number]: string[] }>({});
  const [activeSuggestionIndex, setActiveSuggestionIndex] = useState<{ [key: number]: number }>({});

  const handleInputChange = (ruleIndex: number, value: string) => {
    setSyscallInputValues({
      ...syscallInputValues,
      [ruleIndex]: value,
    });

    if (value.trim()) {
      const suggestions = getSyscallSuggestions(value.trim(), 10);
      setSyscallSuggestions({
        ...syscallSuggestions,
        [ruleIndex]: suggestions,
      });
      setActiveSuggestionIndex({
        ...activeSuggestionIndex,
        [ruleIndex]: -1,
      });
    } else {
      setSyscallSuggestions({
        ...syscallSuggestions,
        [ruleIndex]: [],
      });
    }
  };

  const handleKeyDown = (
    ruleIndex: number,
    e: React.KeyboardEvent<HTMLInputElement>,
    onAdd: (syscall: string) => void
  ) => {
    const suggestions = syscallSuggestions[ruleIndex] || [];
    const activeIndex = activeSuggestionIndex[ruleIndex] ?? -1;

    if (e.key === 'Enter') {
      e.preventDefault();
      if (activeIndex >= 0 && activeIndex < suggestions.length) {
        onAdd(suggestions[activeIndex]);
        setSyscallSuggestions({
          ...syscallSuggestions,
          [ruleIndex]: [],
        });
        clearInput(ruleIndex);
      } else {
        const value = syscallInputValues[ruleIndex] || e.currentTarget.value;
        if (value.trim()) {
          onAdd(value);
          setSyscallSuggestions({
            ...syscallSuggestions,
            [ruleIndex]: [],
          });
          clearInput(ruleIndex);
        }
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (suggestions.length > 0) {
        setActiveSuggestionIndex({
          ...activeSuggestionIndex,
          [ruleIndex]: activeIndex < suggestions.length - 1 ? activeIndex + 1 : 0,
        });
      }
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (suggestions.length > 0) {
        setActiveSuggestionIndex({
          ...activeSuggestionIndex,
          [ruleIndex]: activeIndex > 0 ? activeIndex - 1 : suggestions.length - 1,
        });
      }
    } else if (e.key === 'Escape') {
      setSyscallSuggestions({
        ...syscallSuggestions,
        [ruleIndex]: [],
      });
    }
  };

  const clearInput = (ruleIndex: number) => {
    setSyscallInputValues({
      ...syscallInputValues,
      [ruleIndex]: '',
    });
  };

  const clearSuggestions = (ruleIndex: number) => {
    setSyscallSuggestions({
      ...syscallSuggestions,
      [ruleIndex]: [],
    });
  };

  return {
    syscallInputValues,
    syscallSuggestions,
    activeSuggestionIndex,
    handleInputChange,
    handleKeyDown,
    clearInput,
    clearSuggestions,
  };
};
