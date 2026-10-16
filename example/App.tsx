import React, { useCallback, useState } from 'react';
import { Pressable, ScrollView, StatusBar, StyleSheet, Text, View } from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { type Result, runSelfTest } from './src/selfTest';

export default function App() {
  const [results, setResults] = useState<Result[]>(() => runSelfTest());
  const rerun = useCallback(() => setResults(runSelfTest()), []);
  const passed = results.filter((r) => r.ok).length;
  const allPassed = passed === results.length;

  return (
    <SafeAreaProvider>
      <StatusBar barStyle="dark-content" />
      <SafeAreaView style={styles.screen}>
        <ScrollView contentContainerStyle={styles.content}>
          <Text style={styles.title}>react-native-jwt-io</Text>
          <Text style={[styles.summary, allPassed ? styles.pass : styles.fail]} testID="summary">
            Self-test {passed}/{results.length} {allPassed ? 'passed' : 'FAILED'}
          </Text>
          {results.map((r) => (
            <View key={r.name} style={styles.row}>
              <Text style={[styles.name, r.ok ? styles.pass : styles.fail]}>
                {r.ok ? 'PASS' : 'FAIL'} {r.name}
              </Text>
              <Text style={styles.detail}>{r.detail}</Text>
            </View>
          ))}
          <Pressable onPress={rerun} style={styles.button} accessibilityRole="button">
            <Text style={styles.buttonText}>Run again</Text>
          </Pressable>
        </ScrollView>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: '#fff' },
  content: { padding: 16 },
  title: { fontSize: 20, fontWeight: '600' },
  summary: { fontSize: 16, fontWeight: '600', marginTop: 4, marginBottom: 16 },
  row: { marginBottom: 10 },
  name: { fontSize: 14, fontWeight: '600' },
  detail: { fontSize: 12, color: '#444' },
  pass: { color: '#0a7d2c' },
  fail: { color: '#c0262d' },
  button: { marginTop: 12, padding: 12, borderRadius: 8, backgroundColor: '#1f6feb', alignItems: 'center' },
  buttonText: { color: '#fff', fontWeight: '600' },
});
